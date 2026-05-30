"""Tests for Home Network Management feature."""

import os
import subprocess
from datetime import datetime, timedelta
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

    @pytest.fixture(autouse=True)
    def _stub_moca_fetch(self, mocker):
        """Backlog #42 added a real Verizon-MoCA HTTP call into the scan
        loop. Without this autouse stub, parallel test runs would hit the
        live router via real keyring credentials -- non-deterministic and
        fragile. Stub to "no creds" by default; tests that care about the
        MoCA path live in TestVerizonMocaIntegration where they override
        this with their own explicit mock."""
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={"error": "No creds"},
        )

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
        # Now 3 errors: Verizon devices, Verizon MoCA (#42), Orbi.
        assert len(data["errors"]) == 3
        assert any("Verizon" in e and "Connection refused" in e for e in data["errors"])
        assert any("Verizon MoCA" in e for e in data["errors"])
        assert any("Orbi" in e for e in data["errors"])

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

    def test_update_accepts_wired_via_orbi_satellite(self, client, mocker):
        """Bug fix 2026-05-13: new wired_via value lets users declare a
        device as an Orbi satellite for manual-attestation topology."""
        inv = {
            "devices": {"28:94:01:40:58:F6": {"mac": "28:94:01:40:58:F6"}},
            "last_scan": None,
        }
        mocker.patch("homenet._load_homenet_inventory", return_value=inv)
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "28:94:01:40:58:F6", "wired_via": "orbi_satellite"},
        )
        assert resp.status_code == 200
        assert inv["devices"]["28:94:01:40:58:F6"]["wired_via"] == "orbi_satellite"

    def test_update_accepts_via_orbi_satellite(self, client, mocker):
        """Per-client AP attestation: the new via_orbi_satellite field
        sets the parent satellite for a wireless device."""
        inv = {
            "devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF"}},
            "last_scan": None,
        }
        mocker.patch("homenet._load_homenet_inventory", return_value=inv)
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:DD:EE:FF", "via_orbi_satellite": "28:94:01:40:58:F6"},
        )
        assert resp.status_code == 200
        assert inv["devices"]["AA:BB:CC:DD:EE:FF"]["via_orbi_satellite"] == "28:94:01:40:58:F6"

    def test_update_rejects_invalid_via_orbi_satellite_format(self, client, mocker):
        """Validation: via_orbi_satellite must look like a MAC or be empty."""
        inv = {
            "devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF"}},
            "last_scan": None,
        }
        mocker.patch("homenet._load_homenet_inventory", return_value=inv)
        mocker.patch("homenet._save_homenet_inventory")
        client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:DD:EE:FF", "via_orbi_satellite": "not-a-mac"},
        )
        # Garbage value silently ignored -- the field is NOT set
        assert "via_orbi_satellite" not in inv["devices"]["AA:BB:CC:DD:EE:FF"]


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


class TestVerizonMocaParsing:
    """Backlog #42: parse_verizon_moca_devices() unpacks the CR1000A's
    /cgi/cgi_net_connections.js into a list of MoCA-bridge MACs.

    Captured fixture below is structurally identical to the live data
    seen on 2026-05-05 against firmware 3.6.0.3_BD; MAC addresses have
    been anonymised to documentation-prefix-safe values so the fixture
    can live in the repo. The parser is tolerant of minor format drift
    (the firmware's typo "devcie" / a future fix to "device", whitespace,
    quote style) -- those tolerances are exercised by separate tests.
    """

    # Realistic but anonymised: 4 MoCA bridges + 1 set-top-box style entry,
    # plus the gateway's own MoCA-LAN MAC in get_moca_state. The "devcie"
    # typo is preserved verbatim because that's what live firmware emits.
    FIXTURE_NET_CONNECTIONS = """
addROD("wan_phy_status", [['ETHWAN','Up','fe80::dead:beef'],['MOCAWAN','Up','fe80::dead:beef']]);
addROD("get_moca_state", [['MOCALAN','Up','02:00:00:AA:00:43','956374202','1259957627'],['MOCAWAN','Down','','956374202','1259957627']]);
addROD("get_moca_lan_coordinator", "gateway");
addROD("get_moca_lan_devcie", [['02:00:00:11:11:01','3260','3327'],['02:00:00:11:11:02','3359','3374'],['02:00:00:11:11:03','604','654'],['02:00:00:11:11:04','3210','3222'],['02:00:00:11:11:05','3326','3316'],]);
addROD("get_ipv6_link_local_addr", [['lan1','fe80::dead:beef/64']]);
"""

    def test_parses_all_moca_bridges_from_devcie_typo_key(self):
        from homenet import parse_verizon_moca_devices

        result = parse_verizon_moca_devices(self.FIXTURE_NET_CONNECTIONS)
        assert result["ok"] is True
        assert len(result["moca_devices"]) == 5
        macs = {d["mac"] for d in result["moca_devices"]}
        assert "02:00:00:11:11:01" in macs
        assert "02:00:00:11:11:05" in macs
        # MACs come out canonical upper-colon
        assert all(":" in d["mac"] and d["mac"] == d["mac"].upper() for d in result["moca_devices"])

    def test_parses_signal_metrics_per_bridge(self):
        """The two PHY-rate values per row -- exposed as signal_a / signal_b
        because the firmware doesn't document the schema."""
        from homenet import parse_verizon_moca_devices

        result = parse_verizon_moca_devices(self.FIXTURE_NET_CONNECTIONS)
        bridge0 = next(d for d in result["moca_devices"] if d["mac"] == "02:00:00:11:11:01")
        assert bridge0["signal_a"] == "3260"
        assert bridge0["signal_b"] == "3327"

    def test_parses_gateway_moca_lan_state(self):
        """get_moca_state row tagged MOCALAN gives us the CR1000A's own
        MoCA-LAN MAC + interface state. The scan loop uses this to skip
        the gateway from being double-counted as a bridge."""
        from homenet import parse_verizon_moca_devices

        result = parse_verizon_moca_devices(self.FIXTURE_NET_CONNECTIONS)
        assert result["moca_lan_mac"] == "02:00:00:AA:00:43"
        assert result["moca_lan_state"] == "Up"

    def test_coordinator_value_passes_through(self):
        from homenet import parse_verizon_moca_devices

        result = parse_verizon_moca_devices(self.FIXTURE_NET_CONNECTIONS)
        assert result["coordinator"] == "gateway"

    def test_handles_corrected_devcie_to_device_spelling(self):
        """Defensive: if Verizon ever fixes the 'devcie' typo to 'device'
        in a future firmware release, the parser must keep working without
        any code change. This is the most likely format drift."""
        from homenet import parse_verizon_moca_devices

        fixed_spelling = self.FIXTURE_NET_CONNECTIONS.replace("get_moca_lan_devcie", "get_moca_lan_device")
        result = parse_verizon_moca_devices(fixed_spelling)
        assert result["ok"] is True
        assert len(result["moca_devices"]) == 5

    def test_empty_response_returns_error(self):
        from homenet import parse_verizon_moca_devices

        result = parse_verizon_moca_devices("")
        assert "error" in result

    def test_response_without_moca_data_returns_empty_list(self):
        """Response that's valid JS but contains no MoCA keys -- still
        ok=True with an empty list, not an error. Different from a
        truncated response (which can't be distinguished from auth-rejection
        by the parser)."""
        from homenet import parse_verizon_moca_devices

        # Some non-MoCA cgi page -- valid format, irrelevant content
        no_moca = """addROD("hardware_model", 'CR1000A');
addROD("router_version", '3.6.0.3_BD');"""
        result = parse_verizon_moca_devices(no_moca)
        assert result["ok"] is True
        assert result["moca_devices"] == []

    def test_skips_malformed_mac_rows(self):
        """Rows whose first element isn't a valid MAC -- skip silently
        rather than raising. Defensive against firmware adding header rows
        or future schema changes that break the simple [[mac, ...]] shape."""
        from homenet import parse_verizon_moca_devices

        malformed = """addROD("get_moca_lan_devcie", [['not-a-mac','x','y'],['02:00:00:11:11:01','3260','3327'],['','',''],]);"""
        result = parse_verizon_moca_devices(malformed)
        assert result["ok"] is True
        assert len(result["moca_devices"]) == 1
        assert result["moca_devices"][0]["mac"] == "02:00:00:11:11:01"

    def test_normalises_hyphenated_macs_to_colons(self):
        """Some firmware versions emit hyphen-separated MACs. Normalise
        to upper-colon to match the inventory canonical form."""
        from homenet import parse_verizon_moca_devices

        hyphenated = """addROD("get_moca_lan_devcie", [['02-00-00-11-11-01','3260','3327'],]);"""
        result = parse_verizon_moca_devices(hyphenated)
        assert result["moca_devices"][0]["mac"] == "02:00:00:11:11:01"


class TestVerizonMocaIntegration:
    """Backlog #42: scan-loop integration -- _verizon_get_moca_devices()
    fetches + parses, and homenet_full_scan() merges the result into
    inventory tagged source=verizon-moca-page + wired_via=moca_bridge."""

    def test_no_creds_returns_error_without_network_call(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        # The function must NOT attempt a Session() call when creds missing
        session_mock = mocker.patch("homenet.requests.Session")
        from homenet import _verizon_get_moca_devices

        result = _verizon_get_moca_devices()
        assert "error" in result
        assert "credentials" in result["error"].lower()
        session_mock.assert_not_called()

    def test_login_failure_returns_error(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.cookies.get_dict.return_value = {}  # no sysauth cookie
        login_status = MagicMock()
        login_status.json.return_value = {"loginToken": "abc123"}
        mock_session.get.return_value = login_status
        login_post = MagicMock()
        login_post.status_code = 401
        mock_session.post.return_value = login_post
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _verizon_get_moca_devices

        result = _verizon_get_moca_devices()
        assert "error" in result
        assert "login" in result["error"].lower() or "credentials" in result["error"].lower()

    def test_happy_path_returns_parsed_devices(self, mocker):
        """Successful login + valid response -> parsed list of MoCA bridges."""
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        # Login: token + sysauth cookie present
        mock_session.cookies.get_dict.return_value = {"sysauth": "yes"}

        login_resp = MagicMock()
        login_resp.json.return_value = {"loginToken": "abc"}

        moca_resp = MagicMock()
        moca_resp.text = TestVerizonMocaParsing.FIXTURE_NET_CONNECTIONS

        # session.get hits 2 URLs in order: /loginStatus.cgi, /cgi/cgi_net_connections.js
        mock_session.get.side_effect = [login_resp, moca_resp]
        mock_session.post.return_value = MagicMock(status_code=200)
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _verizon_get_moca_devices

        result = _verizon_get_moca_devices()
        assert result["ok"] is True
        assert len(result["moca_devices"]) == 5

    def test_scan_loop_merges_moca_bridges_with_correct_source_and_wired_via(self, client, mocker):
        """End-to-end: full scan calls _verizon_get_moca_devices and merges
        each bridge into inventory tagged source=verizon-moca-page and
        wired_via=moca_bridge so the topology builder groups them right.

        Uses real Askey OUI (88:DE:7C) so the vendor lookup matches
        _ETHERNET_MOCA_BRIDGE_VENDORS and the auto-tag fires. Bug
        2026-05-12 narrowed auto-tagging to known-bridge vendors (was
        previously unconditional)."""
        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(False, True, ""))
        mocker.patch("homenet._wifi_restore")
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"ok": True, "known_devices": []})
        mocker.patch("homenet._enrich_device_names", side_effect=lambda inv: inv)
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={
                "ok": True,
                "moca_devices": [
                    {"mac": "88:DE:7C:C2:57:36", "signal_a": "3260", "signal_b": "3327"},
                    {"mac": "88:DE:7C:C2:57:37", "signal_a": "3359", "signal_b": "3374"},
                ],
                "moca_lan_mac": "78:67:0E:BD:A4:43",
                "moca_lan_state": "Up",
                "coordinator": "gateway",
            },
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        saved = {}
        mocker.patch("homenet._save_homenet_inventory", side_effect=lambda inv: saved.update(inv))
        from homenet import homenet_full_scan

        result = homenet_full_scan()
        assert result["ok"] is True
        # Both Askey bridges in inventory
        assert "88:DE:7C:C2:57:36" in saved["devices"]
        assert "88:DE:7C:C2:57:37" in saved["devices"]
        # Tagged correctly -- Askey OUI is a known-bridge vendor so auto-tag fires
        b1 = saved["devices"]["88:DE:7C:C2:57:36"]
        assert b1["source"] == "verizon-moca-page"
        assert b1["wired_via"] == "moca_bridge"

    def test_scan_loop_does_not_auto_tag_commscope_as_bridge(self, client, mocker):
        """Bug 2026-05-12 'I only have 4 MoCAs': Commscope/Arris are
        Verizon FiOS STBs that appear on the MoCA-LAN page but are NOT
        Ethernet-to-coax bridges. They must NOT get auto-tagged as
        moca_bridge. The user can explicitly tag wired_via=moca_bridge
        via the edit modal if they really have a Commscope bridge."""
        from homenet import _mac_vendor

        commscope_mac = "B0:5D:D4:76:2A:C0"
        # Pre-condition: the MAC really resolves to Commscope in our OUI db
        assert "commscope" in (_mac_vendor(commscope_mac) or "").lower()

        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(False, True, ""))
        mocker.patch("homenet._wifi_restore")
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"ok": True, "known_devices": []})
        mocker.patch("homenet._enrich_device_names", side_effect=lambda inv: inv)
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={
                "ok": True,
                "moca_devices": [
                    {"mac": commscope_mac, "signal_a": "3260", "signal_b": "3327"},
                ],
                "moca_lan_mac": "78:67:0E:BD:A4:43",
                "moca_lan_state": "Up",
                "coordinator": "gateway",
            },
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        saved = {}
        mocker.patch("homenet._save_homenet_inventory", side_effect=lambda inv: saved.update(inv))
        from homenet import homenet_full_scan

        homenet_full_scan()
        # Commscope is in inventory (we want to surface it)...
        assert commscope_mac in saved["devices"]
        # ...but NOT auto-tagged as a bridge -- it stays empty so the
        # topology builder doesn't spawn a phantom column.
        assert saved["devices"][commscope_mac]["wired_via"] == ""

    def test_scan_loop_skips_gateway_moca_lan_mac(self, client, mocker):
        """The CR1000A's own MoCA-LAN MAC must NOT be merged as a bridge --
        it's the gateway. If the moca_lan_mac shows up in moca_devices
        (firmware quirk) the scan loop skips it."""
        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(False, True, ""))
        mocker.patch("homenet._wifi_restore")
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"ok": True, "known_devices": []})
        mocker.patch("homenet._enrich_device_names", side_effect=lambda inv: inv)
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={
                "ok": True,
                "moca_devices": [
                    {"mac": "02:00:00:AA:00:43", "signal_a": "0", "signal_b": "0"},  # the gateway itself
                    {"mac": "02:00:00:11:11:01", "signal_a": "3260", "signal_b": "3327"},
                ],
                "moca_lan_mac": "02:00:00:AA:00:43",
                "moca_lan_state": "Up",
                "coordinator": "gateway",
            },
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        saved = {}
        mocker.patch("homenet._save_homenet_inventory", side_effect=lambda inv: saved.update(inv))
        from homenet import homenet_full_scan

        homenet_full_scan()
        # Gateway MoCA-LAN MAC NOT merged as a bridge
        assert "02:00:00:AA:00:43" not in saved["devices"]
        # Real bridge IS merged
        assert "02:00:00:11:11:01" in saved["devices"]

    def test_scan_loop_records_error_on_moca_fetch_failure(self, client, mocker):
        """If MoCA fetch fails, the rest of the scan must complete and
        the error is appended to the errors list (not raised)."""
        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(False, True, ""))
        mocker.patch("homenet._wifi_restore")
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"ok": True, "known_devices": []})
        mocker.patch("homenet._enrich_device_names", side_effect=lambda inv: inv)
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={"error": "Verizon router unreachable"},
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        from homenet import homenet_full_scan

        result = homenet_full_scan()
        assert result["ok"] is True
        assert any("Verizon MoCA" in e and "unreachable" in e for e in result.get("errors", []))


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

    @pytest.fixture(autouse=True)
    def _stub_moca_fetch(self, mocker):
        """Same rationale as TestHomeNetScanRoute._stub_moca_fetch -- the
        new MoCA fetch from #42 must be stubbed so parallel test workers
        don't hit the live router via real keyring credentials. Tests
        that care about MoCA override this with their own mock."""
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={"ok": True, "moca_devices": [], "moca_lan_mac": "", "moca_lan_state": "", "coordinator": ""},
        )

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
        # Backlog #42: scan loop also calls _verizon_get_moca_devices.
        # Stub it with an empty success so this test stays focused on
        # the existing 3-source happy path. (The MoCA-specific behaviour
        # has its own coverage in TestVerizonMocaIntegration.)
        mocker.patch(
            "homenet._verizon_get_moca_devices",
            return_value={"ok": True, "moca_devices": [], "moca_lan_mac": "", "moca_lan_state": "", "coordinator": ""},
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
        from datetime import timezone

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
        from datetime import timezone

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
        from datetime import timezone

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
        from datetime import timezone

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
        from datetime import timezone

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

    def test_corrupted_conn_ap_mac_is_dropped_to_empty(self):
        """Bug 2026-05-12: the RBRE960 firmware was observed emitting a
        28-hex-char string in <ConnAPMAC> for satellite-connected clients
        (e.g. `22656C28:2C222294:61622201:6168`). Without validation that
        garbage poisoned the inventory and 24/43 wireless devices ended up
        in the 'Orbi mesh (AP unknown)' bucket. Parser must drop bad
        values to '' rather than store them."""
        from homenet import _parse_orbi_soap

        xml = """<Device>
        <IP>10.0.0.50</IP>
        <Name>FireStick</Name>
        <MAC>AA:BB:CC:DD:EE:FF</MAC>
        <ConnAPMAC>22656C28:2C222294:61622201:6168</ConnAPMAC>
        </Device>"""
        devs = _parse_orbi_soap(xml)
        assert len(devs) == 1
        assert devs[0]["conn_ap_mac"] == ""

    def test_corrupted_conn_ap_mac_captures_debug_sample(self, tmp_path, monkeypatch):
        """When the parser sees a malformed ConnAPMAC it should write the
        raw response to ~/homenet_orbi_debug.xml so the user can attach it
        to a bug report. Single-shot per process to avoid disk spam."""

        import homenet

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path) if p == "~" else p)
        monkeypatch.setattr(homenet, "_orbi_bad_connapmac_sample_captured", False)
        xml = """<Device><MAC>AA:BB:CC:DD:EE:FF</MAC><ConnAPMAC>not-a-real-mac</ConnAPMAC></Device>"""
        homenet._parse_orbi_soap(xml)
        sample = tmp_path / "homenet_orbi_debug.xml"
        assert sample.exists(), "Bad-ConnAPMAC parser should write a debug sample"
        contents = sample.read_text(encoding="utf-8")
        assert "<ConnAPMAC>not-a-real-mac</ConnAPMAC>" in contents
        assert "ConnAPMAC" in contents

    def test_corrupted_conn_ap_mac_capture_is_single_shot(self, tmp_path, monkeypatch):
        """Avoid filling the disk with one capture per topology refresh --
        only the first malformed parse per process writes the file."""

        import homenet

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path) if p == "~" else p)
        monkeypatch.setattr(homenet, "_orbi_bad_connapmac_sample_captured", False)
        homenet._parse_orbi_soap("<Device><MAC>AA:BB:CC:DD:EE:FF</MAC><ConnAPMAC>bad</ConnAPMAC></Device>")
        sample = tmp_path / "homenet_orbi_debug.xml"
        first_mtime = sample.stat().st_mtime_ns
        # Second bad parse must NOT rewrite the file.
        homenet._parse_orbi_soap("<Device><MAC>FF:EE:DD:CC:BB:AA</MAC><ConnAPMAC>also-bad</ConnAPMAC></Device>")
        assert sample.stat().st_mtime_ns == first_mtime


class TestLoadInventorySanitisesBadConnApMac:
    """Bug 2026-05-12: inventory files written before the parser hardened
    have corrupt conn_ap_mac values (24 of 43 wireless devices on the
    user's network). Sanitise on load so the topology builder gets clean
    data without waiting for a fresh Orbi scan."""

    def test_load_drops_bad_conn_ap_mac_from_persisted_inventory(self, tmp_path, monkeypatch):
        import json

        import homenet

        f = tmp_path / "homenet_inventory.json"
        f.write_text(
            json.dumps(
                {
                    "devices": {
                        "AA:BB:CC:DD:EE:FF": {
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "conn_ap_mac": "22656C28:2C222294:61622201:6168",  # corrupt
                        },
                        "11:22:33:44:55:66": {
                            "mac": "11:22:33:44:55:66",
                            "conn_ap_mac": "28:94:01:3F:73:E1",  # good
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        # Reset module flags so a prior test's failure doesn't leak
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        devs = inv["devices"]
        assert devs["AA:BB:CC:DD:EE:FF"]["conn_ap_mac"] == "", "Corrupt value must be cleared"
        assert devs["11:22:33:44:55:66"]["conn_ap_mac"] == "28:94:01:3F:73:E1", "Valid value preserved"


class TestProductionInventoryFileIsolation:
    """Regression guard for the structural fix that closes the gap behind
    the 2026-05-08 'MoCA names disappeared' incident.

    RCA finding: pytest pre-commit hooks could write to the user's REAL
    homenet_inventory.json because HOMENET_INVENTORY_FILE was a module
    constant pointing at the production path. A leaky test that ran
    _save_homenet_inventory without monkeypatching the path would clobber
    user state.

    Fix lives in conftest.py: an autouse session-scoped fixture that
    redirects HOMENET_INVENTORY_FILE to a tmp_path. This test verifies
    the fixture is active -- if someone removes it, the production path
    is exposed again and the assertion fires."""

    def test_homenet_inventory_file_is_redirected_to_tmp_path(self, tmp_path_factory):
        import homenet

        path = homenet.HOMENET_INVENTORY_FILE
        # The session fixture sets this to something under the pytest
        # tmp_path tree. The exact path is per-session and unpredictable
        # but it MUST NOT be the production path.
        production_paths = (
            r"C:\shigsapps\windesktopmgr\homenet_inventory.json",
            "C:/shigsapps/windesktopmgr/homenet_inventory.json",
        )
        for prod in production_paths:
            assert path.lower() != prod.lower(), (
                f"HOMENET_INVENTORY_FILE points at production path {path!r}. "
                "The _isolate_homenet_inventory_file fixture in conftest.py "
                "should have redirected this. If you removed that fixture, "
                "restore it -- any test that accidentally writes to the "
                "production file would clobber the user's friendly_names + "
                "categories + wired_via attestations."
            )
        # And the path SHOULD live under pytest's tmp tree
        assert "tmp" in path.lower() or "temp" in path.lower(), (
            f"HOMENET_INVENTORY_FILE = {path!r} doesn't look like a pytest tmp path"
        )


class TestInventoryLoadFailSafeAgainstStateWipe:
    """RCA for 2026-05-12 'MoCA names disappeared' incident.

    Pre-fix flow: _load_homenet_inventory caught EVERY exception silently
    and returned {"devices": {}, "last_scan": None}. A subsequent scan
    would merge into that empty inventory, then _save_homenet_inventory
    would persist the empty-but-with-new-scan-data result -- clobbering
    every user-attested friendly_name / category / wired_via /
    behind_moca_bridge value. Trigger: a single transient JSON parse
    failure (partial-write race, encoding hiccup, disk hiccup) was
    enough to wipe months of user attestation.

    Post-fix:
      1. Load failure sets a module-level _inventory_load_failed flag
         and prints a CRITICAL log message instead of silently
         returning empty.
      2. _save_homenet_inventory CHECKS that flag and REFUSES to write
         while load is failing.
      3. _save_homenet_inventory writes atomically (tmp + os.replace)
         so no partial-write window can corrupt the file in the future.
    """

    def test_load_failure_sets_flag(self, tmp_path, monkeypatch):
        import homenet

        # Create a deliberately-corrupt JSON file (truncated mid-value)
        f = tmp_path / "homenet_inventory.json"
        f.write_text('{"devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:D', encoding="utf-8")
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        # Load returns empty but sets the failure flag
        assert inv == {"devices": {}, "last_scan": None}
        assert homenet._inventory_load_failed is True

    def test_save_refuses_when_load_failed(self, tmp_path, monkeypatch, capsys):
        """Save must not overwrite the corrupt-but-preserved file."""
        import homenet

        f = tmp_path / "homenet_inventory.json"
        original = '{"devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:D'  # truncated
        f.write_text(original, encoding="utf-8")
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        # Trigger load failure -> flag set
        homenet._load_homenet_inventory()
        assert homenet._inventory_load_failed is True
        # Now attempt to save -- must be refused
        homenet._save_homenet_inventory({"devices": {"01:02:03:04:05:06": {"mac": "01:02:03:04:05:06"}}})
        # File content must be unchanged
        assert f.read_text(encoding="utf-8") == original
        out = capsys.readouterr().out
        assert "REFUSING to save" in out

    def test_save_writes_atomically_via_tmp_rename(self, tmp_path, monkeypatch):
        """No partial-write window: tmp file then os.replace."""
        import homenet

        f = tmp_path / "homenet_inventory.json"
        f.write_text('{"devices": {}, "last_scan": null}', encoding="utf-8")
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        new_inv = {
            "devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF", "friendly_name": "Living Room"}},
            "last_scan": "2026-05-13T00:00:00",
        }
        homenet._save_homenet_inventory(new_inv)
        import json

        # File must parse and contain the new data
        loaded = json.loads(f.read_text(encoding="utf-8"))
        assert loaded["devices"]["AA:BB:CC:DD:EE:FF"]["friendly_name"] == "Living Room"
        # No leftover tmp file
        assert not (tmp_path / "homenet_inventory.json.tmp").exists()

    def test_load_success_clears_prior_failure_flag(self, tmp_path, monkeypatch):
        """Once a valid file is loaded, the flag is cleared so saves resume."""
        import json

        import homenet

        f = tmp_path / "homenet_inventory.json"
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        # Set the flag manually then load a valid file
        monkeypatch.setattr(homenet, "_inventory_load_failed", True)
        f.write_text(json.dumps({"devices": {}, "last_scan": None}), encoding="utf-8")
        homenet._load_homenet_inventory()
        assert homenet._inventory_load_failed is False

    def test_load_first_run_no_file_returns_empty_no_failure(self, tmp_path, monkeypatch):
        """First-run case: no file exists -> empty inventory + flag stays False."""
        import homenet

        f = tmp_path / "homenet_inventory.json"
        assert not f.exists()
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        assert inv == {"devices": {}, "last_scan": None}
        assert homenet._inventory_load_failed is False


class TestPhantomMocaBridgeMigration:
    """Bug 2026-05-12: user reported '4 MoCAs but topology shows 5'.

    Root cause: _verizon_get_moca_devices returns ALL endpoints on the
    coax network, and the post-merge auto-tag set wired_via=moca_bridge
    on every one of them -- including Commscope/Arris devices which are
    almost always Verizon FiOS set-top boxes (built-in MoCA receivers,
    not network bridges).

    Fix: only auto-tag KNOWN-bridge vendors (Askey, Actiontec, Hitron,
    Westell, GoCoax, ScreenBeam, Motorola Mobility). Commscope/Arris
    stay un-tagged on auto-discovery. Existing inventory entries get
    migrated on load -- their phantom wired_via tag is cleared so they
    fall out of the bridge bucket.
    """

    def test_load_clears_phantom_commscope_tag(self, tmp_path, monkeypatch):
        import json

        import homenet

        f = tmp_path / "homenet_inventory.json"
        f.write_text(
            json.dumps(
                {
                    "devices": {
                        # Auto-tagged Commscope STB -- phantom bridge
                        "B0:5D:D4:76:2A:C0": {
                            "mac": "B0:5D:D4:76:2A:C0",
                            "vendor": "Commscope",
                            "source": "verizon-moca-page",
                            "wired_via": "moca_bridge",
                            "friendly_name": "",
                        },
                        # Real Askey bridge -- keep
                        "88:DE:7C:C2:57:36": {
                            "mac": "88:DE:7C:C2:57:36",
                            "vendor": "ASKEY COMPUTER CORP",
                            "source": "verizon-moca-page",
                            "wired_via": "moca_bridge",
                            "friendly_name": "",
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        devs = inv["devices"]
        # Commscope -- cleared
        assert devs["B0:5D:D4:76:2A:C0"]["wired_via"] == ""
        # Askey -- preserved
        assert devs["88:DE:7C:C2:57:36"]["wired_via"] == "moca_bridge"

    def test_load_preserves_commscope_tag_when_children_attached(self, tmp_path, monkeypatch):
        """If the user explicitly assigned a child device to a Commscope
        bridge, they intend it to be a bridge -- migration must NOT clear it."""
        import json

        import homenet

        f = tmp_path / "homenet_inventory.json"
        f.write_text(
            json.dumps(
                {
                    "devices": {
                        "B0:5D:D4:76:2A:C0": {
                            "mac": "B0:5D:D4:76:2A:C0",
                            "vendor": "Commscope",
                            "source": "verizon-moca-page",
                            "wired_via": "moca_bridge",
                        },
                        # A child device attached via behind_moca_bridge
                        "AA:BB:CC:DD:EE:FF": {
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "behind_moca_bridge": "B0:5D:D4:76:2A:C0",
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        # User intent preserved
        assert inv["devices"]["B0:5D:D4:76:2A:C0"]["wired_via"] == "moca_bridge"

    def test_load_only_migrates_verizon_moca_page_source(self, tmp_path, monkeypatch):
        """Devices added via add-manual or other sources are not auto-tagged
        by us -- user attested their wired_via. Don't second-guess them."""
        import json

        import homenet

        f = tmp_path / "homenet_inventory.json"
        f.write_text(
            json.dumps(
                {
                    "devices": {
                        # Manually added by user as a bridge
                        "B0:5D:D4:76:2A:C0": {
                            "mac": "B0:5D:D4:76:2A:C0",
                            "vendor": "Commscope",
                            "source": "manual",  # not verizon-moca-page
                            "wired_via": "moca_bridge",
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(homenet, "HOMENET_INVENTORY_FILE", str(f))
        monkeypatch.setattr(homenet, "_inventory_load_failed", False)
        inv = homenet._load_homenet_inventory()
        # Source != verizon-moca-page -> migration doesn't touch it
        assert inv["devices"]["B0:5D:D4:76:2A:C0"]["wired_via"] == "moca_bridge"
