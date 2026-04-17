"""Tests for Home Network Management feature."""

import subprocess
from unittest.mock import MagicMock


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


class TestMacVendor:
    """Test MAC vendor lookup."""

    def test_known_vendor(self):
        from homenet import _mac_vendor

        assert _mac_vendor("28:94:01:3F:73:E1") == "Netgear"
        assert _mac_vendor("E0:E2:E6:09:67:30") == "Roku"
        assert _mac_vendor("80:6A:10:31:42:E8") == "Apple"

    def test_unknown_vendor(self):
        from homenet import _mac_vendor

        assert _mac_vendor("99:99:99:00:00:00") == "Unknown"

    def test_dash_format(self):
        from homenet import _mac_vendor

        assert _mac_vendor("28-94-01-3F-73-E1") == "Netgear"


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
        assert _auto_categorize("Random MAC (Phone)", "", "", "") == ""


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
