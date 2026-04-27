"""
homenet.py — Home Network Management module for WinDesktopMgr.

Device inventory, router integration (Verizon CR1000A, Netgear Orbi,
TP-Link switch), credential management via Windows Credential Manager.

Extracted from windesktopmgr.py to reduce main file size and improve
maintainability.
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify, request

# IEEE OUI vendor lookup (backlog #10). Optional dep -- collector degrades
# to the curated _MAC_VENDORS dict only if mac-vendor-lookup isn't
# installed or its cached IEEE registry is missing.
try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError

    _IEEE_LOOKUP: "MacLookup | None" = MacLookup()
except Exception:  # noqa: BLE001 -- any import / init failure -> no IEEE lookup
    _IEEE_LOOKUP = None

    class VendorNotFoundError(Exception):  # type: ignore[no-redef]
        """Placeholder so call sites can except cleanly when mac-vendor-lookup is absent."""


# Serialises IEEE lookup calls. Rationale: mac_vendor_lookup is built on
# asyncio -- MacLookup.lookup() wraps the underlying async call with
# ``loop.run_until_complete()`` on a single private event loop shared by
# the instance. Multi-threaded callers (Flask ``threaded=True`` + parallel
# homenet scans + dashboard fan-out) race on that shared loop and some
# calls silently fail -- observed live 2026-04-23 as 14/76 devices still
# showing "Unknown" even though REPL on identical code + env resolved
# every one of them. Holding this lock around the lookup forces sequential
# access to the event loop and eliminates the race.
_ieee_lookup_lock = threading.Lock()


APP_DIR = os.path.dirname(os.path.abspath(__file__))

homenet_bp = Blueprint("homenet", __name__)

# Credential service names used with keyring
_HOMENET_CRED_PREFIX = "wdm-homenet"
HOMENET_INVENTORY_FILE = os.path.join(APP_DIR, "homenet_inventory.json")
HOMENET_SCAN_HISTORY_FILE = os.path.join(APP_DIR, "homenet_scan_history.json")
_homenet_lock = threading.Lock()

# ── MAC vendor OUI lookup (top entries for quick identification) ─────────────
_MAC_VENDORS = {
    "28:94:01": "Netgear",
    "48:3F:DA": "Netgear",
    "7C:87:CE": "Netgear",
    "74:AB:93": "Netgear",
    "9C:76:13": "Netgear",
    "D0:C9:07": "Netgear",
    "00:03:7F": "Actiontec",
    "40:F5:20": "Verizon",
    "60:74:F4": "Verizon",
    "E0:E2:E6": "Roku",
    "00:22:6C": "LinkSys",
    "D8:28:C9": "Samsung",
    "90:48:6C": "Samsung",
    "64:33:DB": "Espressif (IoT)",
    "34:6F:92": "Espressif (IoT)",
    "A8:42:E3": "Alexa/Amazon",
    "DC:A6:33": "Amazon",
    "F8:F0:05": "Amazon",
    "44:3D:54": "Amazon",
    "00:06:78": "Marantz/Denon",
    "80:6A:10": "Apple",
    "AC:0B:FB": "Apple",
    "34:20:03": "Apple",
    "2C:05:47": "Apple",
    "0C:EF:15": "Aruba/HPE",
    "CC:A2:19": "TCL/Roku",
    "28:C5:C8": "HP",
    "70:77:81": "Brother",
    "10:97:BD": "Honeywell",
    "64:52:99": "Intel",
    "FA:93:62": "Random MAC (Phone)",
    "5A:95:23": "Random MAC (Phone)",
    # TP-Link
    "50:C7:BF": "TP-Link",
    "74:DA:88": "TP-Link",
    "FC:D7:33": "TP-Link",
    "F8:D1:11": "TP-Link",
    "F8:1A:67": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "F4:EC:38": "TP-Link",
    "F4:83:CD": "TP-Link",
    "F0:F3:36": "TP-Link",
    "EC:88:8F": "TP-Link",
    "EC:26:CA": "TP-Link",
    "EC:17:2F": "TP-Link",
    "E8:DE:27": "TP-Link",
    "E4:D3:32": "TP-Link",
    "DC:FE:18": "TP-Link",
    "D8:5D:4C": "TP-Link",
    "D4:6E:0E": "TP-Link",
    "14:E6:E4": "TP-Link",
    "14:EB:B6": "TP-Link",
    "3C:84:6A": "TP-Link",
    "68:DD:B7": "TP-Link",
    "14:D8:64": "TP-Link",
    "40:ED:00": "TP-Link",
    "30:B5:C2": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "D8:F1:2E": "TP-Link",
    "50:91:E3": "TP-Link",
    "E8:48:B8": "TP-Link",
    "F8:CE:21": "TP-Link",
    "98:DA:C4": "TP-Link",
    "B0:BE:76": "TP-Link",
    "60:32:B1": "TP-Link",
    "C0:06:C3": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "54:AF:97": "TP-Link",
    "AC:84:C6": "TP-Link",
    "DC:62:79": "TP-Link",
}


# Module-level cache: OUI prefix → resolved vendor name. Populated on
# first lookup per prefix, cleared when the app restarts. IEEE lookups
# are fast (in-memory after initial file read) but caching in our
# namespace lets tests reset state cleanly via _vendor_cache.clear().
_vendor_cache: dict[str, str] = {}
_vendor_cache_lock = threading.Lock()


def _is_locally_admin_mac(mac: str) -> bool:
    """True if the MAC's locally-administered bit is set.

    Bit 1 (LSB count) of the first octet = 1 means the MAC was
    self-assigned, not IEEE-issued. Modern iOS / Android randomise
    MACs per-SSID for privacy, so these MACs never resolve to a
    real vendor -- returning "Random MAC (Phone)" is much more
    honest than "Unknown".
    """
    try:
        first_hex = mac.replace(":", "").replace("-", "")[:2]
        return bool(int(first_hex, 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _mac_vendor(mac: str) -> str:
    """Look up vendor for a MAC address with layered sources (backlog #10).

    Priority, highest → lowest:
      1. Curated overrides in _MAC_VENDORS — friendly short names we want
         to keep ("Netgear" vs IEEE's "NETGEAR", "Random MAC (Phone)" for
         known randomised prefixes we've already seen).
      2. IEEE MA-L / MA-M / MA-S registry via ``mac-vendor-lookup`` —
         covers ~36 k manufacturers; replaces the old 65-entry hardcoded
         dict for everything not in #1.
      3. "Random MAC (Phone)" if the locally-admin bit is set and IEEE
         didn't match — catches randomised phone MACs the curated dict
         hasn't memorised yet.
      4. "Unknown" final fallback.

    Results cached by OUI prefix so repeated lookups are O(1).
    """
    if not mac:
        return "Unknown"
    prefix = mac[:8].upper().replace("-", ":")

    # 1. Curated override wins outright
    curated = _MAC_VENDORS.get(prefix)
    if curated:
        return curated

    # 2. Cache check
    with _vendor_cache_lock:
        cached = _vendor_cache.get(prefix)
    if cached is not None:
        return cached

    # 3. IEEE lookup. Serialised via _ieee_lookup_lock because
    # mac_vendor_lookup uses a shared asyncio event loop that races under
    # concurrent calls -- see _ieee_lookup_lock docstring above.
    vendor = ""
    if _IEEE_LOOKUP is not None:
        try:
            with _ieee_lookup_lock:
                vendor = (_IEEE_LOOKUP.lookup(mac) or "").strip()
        except VendorNotFoundError:
            vendor = ""
        except Exception:  # noqa: BLE001 -- any IEEE failure is non-fatal
            vendor = ""

    # 4. Randomised-MAC detection
    if not vendor and _is_locally_admin_mac(mac):
        vendor = "Random MAC (Phone)"

    # Only cache POSITIVE resolutions. A cached "Unknown" poisons the
    # result for the lifetime of the process -- observed post-deploy on
    # 2026-04-23: the first scan after tray restart hit a race where
    # mac-vendor-lookup's IEEE file hadn't finished loading, lookups
    # returned nothing, and "Unknown" got cached. Subsequent scans
    # saw the cache hit and never retried, even though IEEE had since
    # fully loaded. By not caching Unknown, the next call retries and
    # picks up the real vendor once the registry is warm.
    if not vendor:
        return "Unknown"

    with _vendor_cache_lock:
        _vendor_cache[prefix] = vendor
    return vendor


def _get_homenet_cred(device_key: str) -> tuple:
    """Retrieve stored credentials from Windows Credential Manager."""
    try:
        import keyring

        svc = f"{_HOMENET_CRED_PREFIX}-{device_key}"
        pw = keyring.get_password(svc, "admin")
        if pw:
            return ("admin", pw)
        # Try alternate username
        cred = keyring.get_credential(svc, None)
        if cred:
            return (cred.username, cred.password)
    except Exception as e:
        print(f"[HomeNet] keyring error for {device_key}: {e}")
    return (None, None)


def _set_homenet_cred(device_key: str, username: str, password: str) -> bool:
    """Store credentials in Windows Credential Manager."""
    try:
        import keyring

        svc = f"{_HOMENET_CRED_PREFIX}-{device_key}"
        keyring.set_password(svc, username, password)
        return True
    except Exception as e:
        print(f"[HomeNet] keyring set error for {device_key}: {e}")
        return False


def _delete_homenet_cred(device_key: str) -> bool:
    """Delete stored credentials from Windows Credential Manager."""
    try:
        import keyring

        svc = f"{_HOMENET_CRED_PREFIX}-{device_key}"
        user, _ = _get_homenet_cred(device_key)
        if user:
            keyring.delete_password(svc, user)
        return True
    except Exception as e:
        print(f"[HomeNet] keyring delete error for {device_key}: {e}")
        return False


def _list_homenet_creds() -> list:
    """List all configured device credentials (passwords masked)."""
    devices = [
        {"key": "verizon", "label": "Verizon CR1000A", "ip": "192.168.1.1"},
        {"key": "orbi", "label": "Netgear Orbi RBRE960", "ip": "10.0.0.1"},
        {"key": "tplink_switch", "label": "TP-Link TL-SG2218 Switch", "ip": "TBD"},
    ]
    result = []
    for dev in devices:
        user, pw = _get_homenet_cred(dev["key"])
        result.append(
            {
                **dev,
                "configured": user is not None,
                "username": user or "",
                "password_hint": ("••••" + pw[-2:]) if pw and len(pw) > 2 else ("••••" if pw else ""),
            }
        )
    return result


# ── Verizon CR1000A API (reverse-engineered from ha-verizonFiOS) ─────────────


def _arc_md5(text: str) -> str:
    """ArcMD5: SHA512(MD5(text).hex()) — Verizon's custom hash."""
    md5_hex = hashlib.md5(text.encode()).hexdigest()  # noqa: S324
    return hashlib.sha512(md5_hex.encode("ascii")).hexdigest()


def _verizon_encode_password(password: str, token: str) -> str:
    """SHA512(token + ArcMD5(password))."""
    return hashlib.sha512((token + _arc_md5(password)).encode("ascii")).hexdigest()


def _verizon_get_devices() -> dict:
    """
    Connect to Verizon CR1000A and pull device list + topology.
    Uses the reverse-engineered auth flow from ha-verizonFiOS.
    """
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    user, pw = _get_homenet_cred("verizon")
    if not user or not pw:
        return {"error": "No Verizon credentials configured. Add them in Network Settings."}

    base = "https://192.168.1.1"
    session = requests.Session()
    session.verify = False
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": f"{base}/",
            "Origin": base,
        }
    )

    try:
        # Step 1: Get login token
        r = session.get(f"{base}/loginStatus.cgi", timeout=10)
        login_data = r.json()
        token = login_data.get("loginToken", "")
        if not token:
            return {"error": "Could not get login token from Verizon router"}

        # Step 2: Login with hashed credentials
        payload = {
            "luci_username": _arc_md5(user),
            "luci_password": _verizon_encode_password(pw, token),
            "luci_view": "Desktop",
            "luci_token": token,
            "luci_keep_login": "0",
        }
        r = session.post(f"{base}/login.cgi", data=payload, timeout=10, allow_redirects=False)
        if r.status_code not in (200, 302):
            return {"error": f"Verizon login failed (HTTP {r.status_code})"}

        # Check session cookie
        if "sysauth" not in session.cookies.get_dict():
            return {"error": "Verizon login failed — bad credentials or auth changed"}

        # Step 3: Fetch device data from cgi_basic.js
        r = session.get(f"{base}/cgi/cgi_basic.js", timeout=15)
        raw_js = r.text

        # Parse addROD("key", value); calls from the JavaScript response
        devices_raw = _parse_verizon_js(raw_js)

        return {
            "ok": True,
            "router_name": devices_raw.get("router_name", "CR1000A"),
            "hardware_model": devices_raw.get("hardware_model", ""),
            "topology": devices_raw.get("dump_toplogy_map_info", {}),
            "known_devices": devices_raw.get("known_device_list", {}),
            "stations": devices_raw.get("dump_toplogy_station_info", {}),
        }

    except requests.exceptions.ConnectTimeout:
        return {"error": "Verizon router unreachable (192.168.1.1) — check wired connection"}
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to Verizon router — check network"}
    except Exception as e:
        return {"error": f"Verizon API error: {e}"}
    finally:
        session.close()


def _parse_verizon_js(raw_js: str) -> dict:
    """Parse addROD('key', value); calls from Verizon's cgi_basic.js response."""
    result = {}
    # Match: addROD("key", value); or addROD("key", "string");
    pattern = r'addROD\(\s*["\'](\w+)["\']\s*,\s*(.+?)\)\s*;'
    for match in re.finditer(pattern, raw_js, re.DOTALL):
        key = match.group(1)
        val_str = match.group(2).strip()
        # Try to parse as JSON (fix JS quirks: single quotes, trailing commas)
        try:
            cleaned = val_str.replace("'", '"')
            cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
            result[key] = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            # Plain string value
            result[key] = val_str.strip("\"'")
    return result


# ── Netgear Orbi SOAP API ────────────────────────────────────────────────────


def _orbi_get_devices() -> dict:
    """
    Connect to Orbi RBRE960 via SOAP API and pull device list.
    Uses direct SOAP calls (same protocol as pynetgear).
    """
    from xml.sax.saxutils import escape as xml_escape

    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    user, pw = _get_homenet_cred("orbi")
    if not user or not pw:
        return {"error": "No Orbi credentials configured. Add them in Network Settings."}

    # Orbi SOAP endpoint — RBRE960 uses HTTPS on port 443 (not HTTP:5000)
    orbi_ip = "10.0.0.1"
    url = f"https://{orbi_ip}/soap/server_sa/"

    headers = {
        "SOAPAction": "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice2",
        "Content-Type": "text/xml; charset=utf-8",
    }

    soap_body = """<?xml version="1.0" encoding="UTF-8"?>
<v:Envelope xmlns:v="http://schemas.xmlsoap.org/soap/envelope/">
  <v:Header>
    <SessionID>DEF456</SessionID>
  </v:Header>
  <v:Body>
    <M1:GetAttachDevice2 xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1"/>
  </v:Body>
</v:Envelope>"""

    try:
        # First try to log in via SOAP
        login_headers = {
            "SOAPAction": "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate",
            "Content-Type": "text/xml; charset=utf-8",
        }
        login_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<v:Envelope xmlns:v="http://schemas.xmlsoap.org/soap/envelope/">
  <v:Header>
    <SessionID>DEF456</SessionID>
  </v:Header>
  <v:Body>
    <M1:Authenticate xmlns:M1="urn:NETGEAR-ROUTER:service:ParentalControl:1">
      <NewUsername>{xml_escape(user)}</NewUsername>
      <NewPassword>{xml_escape(pw)}</NewPassword>
    </M1:Authenticate>
  </v:Body>
</v:Envelope>"""

        session = requests.Session()
        session.verify = False  # Orbi uses self-signed cert
        # Login via SOAP authentication
        r = session.post(url, data=login_body, headers=login_headers, timeout=10)
        if r.status_code not in (200, 401):
            # 401 is expected first call, triggers auth
            pass

        # Fetch devices (use HTTP Basic auth as fallback)
        r = session.post(url, data=soap_body, headers=headers, timeout=15, auth=(user, pw))

        if r.status_code == 200:
            devices = _parse_orbi_soap(r.text)
            return {"ok": True, "devices": devices}
        else:
            return {"error": f"Orbi SOAP returned HTTP {r.status_code}"}

    except requests.exceptions.ConnectTimeout:
        return {"error": "Orbi unreachable (10.0.0.1) — is Wi-Fi connected?"}
    except requests.exceptions.SSLError:
        return {"error": "Orbi SSL error — router may need firmware update"}
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to Orbi — ensure Wi-Fi is connected to Orbi network"}
    except Exception as e:
        return {"error": f"Orbi API error: {e}"}
    finally:
        session.close()


def _parse_orbi_soap(xml_text: str) -> list:
    """Parse Orbi GetAttachDevice2 SOAP response into device list.

    RBRE960 returns XML with <Device> elements containing child tags:
    <IP>, <Name>, <MAC>, <ConnectionType>, <Linkspeed>, <SignalStrength>,
    <DeviceModel>, <DeviceBrand>, <DeviceTypeV2>, <SSID>, <ConnAPMAC>, etc.

    Also supports legacy @-delimited format from older firmware.
    """
    devices = []

    # Try XML <Device> format first (RBRE960 with current firmware)
    device_blocks = re.findall(r"<Device>(.*?)</Device>", xml_text, re.DOTALL)
    if device_blocks:
        for block in device_blocks:

            def _tag(name, _block=block):
                m = re.search(rf"<{name}>(.*?)</{name}>", _block)
                return m.group(1).strip() if m else ""

            mac = _tag("MAC").upper().replace("-", ":")
            if not mac:
                continue
            # ConnAPMAC tells us which Orbi node (router or satellite) the
            # client is associated with -- needed by the topology diagram
            # (#9). Normalised to upper-colon so it joins cleanly against
            # the satellite MAC list later. Empty when the client is wired.
            conn_ap_mac = _tag("ConnAPMAC").upper().replace("-", ":")
            devices.append(
                {
                    "ip": _tag("IP"),
                    "name": _tag("Name"),
                    "mac": mac,
                    "connection_type": _tag("ConnectionType"),
                    "link_rate": _tag("Linkspeed"),
                    "signal_strength": _tag("SignalStrength"),
                    "device_type": _tag("DeviceTypeV2"),
                    "device_model": _tag("DeviceModel"),
                    "device_brand": _tag("DeviceBrand"),
                    "ssid": _tag("SSID"),
                    "conn_ap_mac": conn_ap_mac,
                    "device_name_user_set": _tag("NameUserSet") == "true",
                }
            )
        return devices

    # Fallback: legacy @-delimited format (older Orbi firmware)
    dev_match = re.search(r"<NewGetAttachDevice2>(.*?)</NewGetAttachDevice2>", xml_text, re.DOTALL)
    if not dev_match:
        return devices

    raw = dev_match.group(1).strip()
    for entry in raw.split("@"):
        parts = entry.split(";")
        if len(parts) >= 4:
            devices.append(
                {
                    "ip": parts[0] if len(parts) > 0 else "",
                    "name": parts[1] if len(parts) > 1 else "",
                    "mac": parts[2] if len(parts) > 2 else "",
                    "connection_type": parts[3] if len(parts) > 3 else "",
                    "link_rate": parts[4] if len(parts) > 4 else "",
                    "signal_strength": parts[5] if len(parts) > 5 else "",
                    "device_type": parts[len(parts) - 1] if len(parts) > 6 else "",
                }
            )
    return devices


# ── TP-Link TL-SG2218 SNMP integration ──────────────────────────────────────


def _tplink_snmp_query(switch_ip: str, community: str = "public") -> dict:
    """
    Query TP-Link TL-SG2218 switch via SNMP for port status, traffic stats,
    and MAC address table.
    Uses synchronous SNMP via pysnmp v7.
    """
    try:
        import asyncio

        from pysnmp.hlapi.v1arch.asyncio import (
            CommunityData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            bulkWalkCmd,
        )
    except ImportError:
        return {"error": "pysnmp not installed. Run: pip install pysnmp"}

    results = {"ports": [], "mac_table": [], "system_info": {}}

    async def _query():  # pragma: no cover — requires live SNMP device
        engine = SnmpEngine()
        target = await UdpTransportTarget.create((switch_ip, 161))
        creds = CommunityData(community)

        # 1. System info (sysDescr, sysName, sysUpTime)
        sys_oids = {
            "sysDescr": "1.3.6.1.2.1.1.1.0",
            "sysName": "1.3.6.1.2.1.1.5.0",
            "sysUpTime": "1.3.6.1.2.1.1.3.0",
        }
        for name, oid in sys_oids.items():
            try:
                async for error_indication, error_status, _, var_binds in bulkWalkCmd(
                    engine, creds, target, 0, 1, ObjectType(ObjectIdentity(oid))
                ):
                    if error_indication or error_status:
                        break
                    for _, val in var_binds:
                        results["system_info"][name] = str(val)
                    break  # Only need first result
            except Exception:
                pass

        # 2. Port status (ifDescr, ifOperStatus, ifSpeed, ifInOctets, ifOutOctets)
        port_data = {}
        oid_map = {
            "ifDescr": "1.3.6.1.2.1.2.2.1.2",
            "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
            "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
            "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
            "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
        }

        for field, base_oid in oid_map.items():
            try:
                async for error_indication, error_status, _, var_binds in bulkWalkCmd(
                    engine, creds, target, 0, 25, ObjectType(ObjectIdentity(base_oid))
                ):
                    if error_indication or error_status:
                        break
                    for oid, val in var_binds:
                        oid_str = str(oid)
                        # Extract ifIndex from OID
                        idx = oid_str.split(".")[-1]
                        if idx not in port_data:
                            port_data[idx] = {"ifIndex": idx}
                        port_data[idx][field] = str(val) if field == "ifDescr" else int(val)
            except Exception:
                pass

        # Convert to list, filter to physical ports
        for _idx, pdata in sorted(port_data.items(), key=lambda x: int(x[0])):
            desc = pdata.get("ifDescr", "")
            if "gigabitEthernet" in desc.lower() or "sfp" in desc.lower():
                status_val = pdata.get("ifOperStatus", 2)
                results["ports"].append(
                    {
                        "port": desc,
                        "ifIndex": pdata["ifIndex"],
                        "status": "up" if status_val == 1 else "down",
                        "speed_mbps": pdata.get("ifSpeed", 0) // 1_000_000,
                        "in_bytes": pdata.get("ifInOctets", 0),
                        "out_bytes": pdata.get("ifOutOctets", 0),
                    }
                )

        # 3. MAC address table (Bridge MIB forwarding database)
        try:
            base_oid = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort
            async for error_indication, error_status, _, var_binds in bulkWalkCmd(
                engine, creds, target, 0, 50, ObjectType(ObjectIdentity(base_oid))
            ):
                if error_indication or error_status:
                    break
                for oid, val in var_binds:
                    oid_str = str(oid)
                    # MAC is encoded in the OID suffix as decimal octets
                    parts = oid_str.replace(base_oid + ".", "").split(".")
                    if len(parts) == 6:
                        mac = ":".join(f"{int(p):02X}" for p in parts)
                        results["mac_table"].append({"mac": mac, "port_index": int(val)})
        except Exception:
            pass

        engine.close()

    try:
        asyncio.run(_query())
    except Exception as e:
        return {"error": f"SNMP query failed: {e}"}

    return {"ok": True, **results}


TPLINK_SWITCH_MAC = "DC:62:79:F3:52:5C"


def _resolve_ip_from_mac(target_mac: str) -> str:
    """Find current IP for a known MAC address via ARP table lookup."""
    target = target_mac.upper().replace("-", ":")
    arp_devices = _arp_scan()
    for d in arp_devices:
        mac = d.get("MAC", "").upper().replace("-", ":")
        if mac == target:
            return d.get("IP", "")
    return ""


def _tplink_get_data() -> dict:
    """Fetch TP-Link switch data using stored credentials (SNMP community string)."""
    user, pw = _get_homenet_cred("tplink_switch")
    if not user or not pw:
        return {"error": "No TP-Link switch credentials configured. Add SNMP community string in Network Settings."}

    # user = switch IP (or "auto"), pw = SNMP community string
    switch_ip = user
    if not switch_ip or switch_ip.lower() == "auto":
        # Auto-discover switch IP from known MAC
        switch_ip = _resolve_ip_from_mac(TPLINK_SWITCH_MAC)
        if not switch_ip:
            return {"error": f"Cannot find TP-Link switch ({TPLINK_SWITCH_MAC}) on network. Is it powered on?"}

    return _tplink_snmp_query(switch_ip, pw)


# ── Device Name Resolution ────────────────────────────────────────────────────

# Auto-categorize devices by vendor name
_VENDOR_CATEGORY_MAP = {
    "Roku": "TV",
    "TCL/Roku": "TV",
    "Samsung": "TV",
    "Apple": "Phone",
    "Alexa/Amazon": "IoT",
    "Amazon": "IoT",
    "Espressif (IoT)": "IoT",
    "Honeywell": "IoT",
    "Brother": "Printer",
    "HP": "Printer",
    "Netgear": "Network",
    "TP-Link": "Network",
    "Actiontec": "Network",
    "Verizon": "Network",
    "Aruba/HPE": "Network",
    "LinkSys": "Network",
    "Intel": "Computer",
    "Random MAC (Phone)": "Phone",
}


# IEEE returns long vendor names like "Amazon Technologies Inc." that don't
# match the curated map keys. Substring patterns let us categorise those
# without maintaining every exact string form. First matching tuple wins
# (order matters — more specific patterns above more generic ones).
_VENDOR_CATEGORY_PATTERNS: tuple[tuple[tuple[str, ...], str], ...] = (
    # TVs / streamers — check before generic "samsung" since Samsung makes both
    (("roku", "chromecast", "google cast", "firestick", "fire tv", "apple tv"), "TV"),
    (("samsung electronics", "lg electronics", "sony", "vizio", "tcl"), "TV"),
    # Printers
    (("brother", "epson", "canon", "lexmark", "xerox", "kyocera"), "Printer"),
    (("hewlett packard", "hewlett-packard", "hp inc", "hp enterprise"), "Printer"),
    # IoT / smart home
    (("amazon technologies", "ring llc", "ring, llc", "blink"), "IoT"),
    (("google, inc", "google llc", "nest labs", "nest lab"), "IoT"),
    (("philips lighting", "signify", "philips hue"), "IoT"),
    (("sonos",), "IoT"),
    (("ecobee", "ecobee inc"), "IoT"),
    (("shelly", "allterco"), "IoT"),
    (("tuya smart", "tuya inc"), "IoT"),
    (("espressif", "itead"), "IoT"),
    (("smartthings", "wyze"), "IoT"),
    # Phones / tablets -- default to Phone for ambiguous mobile-first vendors
    (("apple, inc", "apple inc", "apple computer"), "Phone"),
    (("xiaomi", "oneplus", "huawei", "oppo"), "Phone"),
    # Network gear
    (("netgear", "tp-link", "tplink", "linksys", "ubiquiti", "ubnt", "aruba", "cisco"), "Network"),
    (("actiontec", "arris", "verizon"), "Network"),
    # Storage / NAS
    (("synology", "qnap", "western digital", "seagate"), "Storage"),
    # Computers / SoCs
    (("intel corporate", "intel corp", "dell inc", "lenovo", "asustek"), "Computer"),
    (("microsoft corporation",), "Other"),  # Xbox, Surface, Hyper-V, etc.
)


def _categorise_by_vendor_substring(vendor: str) -> str:
    """Return a category if `vendor` contains any pattern, else "".

    Case-insensitive. Used as a fallback after _VENDOR_CATEGORY_MAP misses
    on an IEEE-sourced long-form vendor name.
    """
    if not vendor:
        return ""
    v = vendor.lower()
    for needles, category in _VENDOR_CATEGORY_PATTERNS:
        if any(n in v for n in needles):
            return category
    return ""


def _dns_resolve_ip(ip: str) -> tuple:
    """Resolve a single IP via reverse DNS.  Returns (ip, hostname) or (ip, "")."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return ip, hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    return ip, ""


def _mdns_resolve_batch(ips: list, timeout_s: float = 3.0) -> dict:
    """Discover Bonjour / mDNS services and map IP → hostname (backlog #10).

    Python-first alternative to shelling out to ``dns-sd`` / ``avahi-browse``.
    Uses the ``zeroconf`` pip package to passively browse a handful of the
    most common service types, collect advertised hostnames, and return
    ``{ip: hostname}`` for any IP in ``ips`` that advertised.

    Covers:
      * Apple devices (``_airplay._tcp``, ``_raop._tcp``)
      * Chromecasts (``_googlecast._tcp``)
      * AirPrint printers (``_ipp._tcp``)
      * HomeKit accessories (``_hap._tcp``)
      * Any device that advertises a web UI (``_http._tcp``)

    Returns an empty dict on import failure, zeroconf init failure, or
    when no IP in ``ips`` advertises within ``timeout_s``. Never raises.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        return {}

    if not ips:
        return {}

    ips_set = set(ips)
    results: dict[str, str] = {}
    results_lock = threading.Lock()

    class _Listener(ServiceListener):
        def _extract(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1000)
            except Exception:  # noqa: BLE001
                return
            if not info:
                return
            server = (info.server or "").rstrip(".")
            if not server:
                return
            try:
                addrs = info.parsed_addresses()
            except Exception:  # noqa: BLE001
                return
            for addr in addrs:
                if addr in ips_set:
                    # Short hostname: strip ".local" and trailing domain
                    short = server.split(".")[0]
                    if short:
                        with results_lock:
                            if addr not in results:
                                results[addr] = short

        def add_service(self, zc, type_, name):
            self._extract(zc, type_, name)

        def update_service(self, zc, type_, name):
            self._extract(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    # Common service types covering the vast majority of home devices.
    # Keeping the list short limits network chatter; adding more means
    # catching more devices at the cost of slightly longer discovery.
    service_types = (
        "_http._tcp.local.",
        "_ipp._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_googlecast._tcp.local.",
        "_hap._tcp.local.",
        "_printer._tcp.local.",
        "_workstation._tcp.local.",
    )

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        browsers = [ServiceBrowser(zc, st, listener) for st in service_types]
        time.sleep(timeout_s)
        for b in browsers:
            try:
                b.cancel()
            except Exception:  # noqa: BLE001
                pass
    except Exception as e:  # noqa: BLE001 -- zeroconf is best-effort
        print(f"[HomeNet] mDNS resolution error: {e}")
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:  # noqa: BLE001
                pass

    return results


def _nbt_resolve_ip(ip: str) -> tuple:
    """Run ``nbtstat -A <ip>`` directly and extract the <00> UNIQUE name.

    Returns (ip, hostname) or (ip, "").
    """
    try:
        # quiet_timeout=True: timeouts on dormant/wireless hosts are expected
        # and handled by the "" fallback below — don't spam the error log
        r = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=5,
            quiet_timeout=True,
        )
        for line in r.stdout.splitlines():
            if "<00>" in line and "UNIQUE" in line:
                parts = line.split()
                if parts:
                    return ip, parts[0].strip()
    except Exception:
        pass
    return ip, ""


def _resolve_names_batch(devices: list) -> dict:
    """
    Resolve hostnames for a batch of devices using multiple methods.
    Returns {ip: resolved_name} dict.

    Phase 0: mDNS / Bonjour broadcast — catches Apple devices, Chromecasts,
             Rokus, AirPrint printers, Sonos, HomeKit, most modern IoT.
             Runs across all subnets the host can reach via multicast.
    Phase 1: Parallel reverse-DNS via ``socket.gethostbyaddr`` for 192.x (wired).
    Phase 2: ``nbtstat -A`` directly for wired IPs that DNS missed.
    Phase 3: ``nbtstat -A`` directly for 10.x (wireless/Orbi) if Wi-Fi is connected.
    """
    results: dict[str, str] = {}
    ips_to_resolve = []

    for dev in devices:
        ip = dev.get("ip", "")
        # Skip if already has a good hostname (not empty, not just an IP)
        hostname = dev.get("hostname", "")
        if ip and (not hostname or hostname == ip or hostname.lower() == "unknown"):
            ips_to_resolve.append(ip)

    if not ips_to_resolve:
        return results

    # Phase 0: mDNS sweeps ALL subnets in one multicast pass, so run it
    # first. Covers devices DNS/NetBIOS can't see (Chromecasts, HomeKit,
    # many IoT). Skipped silently if zeroconf isn't installed.
    try:
        mdns_hits = _mdns_resolve_batch(ips_to_resolve, timeout_s=3.0)
        for ip, name in mdns_hits.items():
            results[ip] = name
    except Exception as e:  # noqa: BLE001 -- mDNS is best-effort
        print(f"[HomeNet] mDNS phase failed: {e}")

    # Remove mDNS-resolved IPs from the list the later phases chase
    ips_to_resolve = [ip for ip in ips_to_resolve if ip not in results]

    # Split IPs by subnet — DNS only works for 192.x (wired/Verizon DHCP).
    # 10.x devices are behind Orbi NAT so reverse DNS always times out.
    wired_ips = [ip for ip in ips_to_resolve if ip.startswith("192.")]
    wireless_ips = [ip for ip in ips_to_resolve if ip.startswith("10.")]

    # Phase 1: Parallel reverse-DNS for 192.x wired devices
    if wired_ips:
        try:
            with ThreadPoolExecutor(max_workers=min(len(wired_ips), 20)) as pool:
                futs = {pool.submit(_dns_resolve_ip, ip): ip for ip in wired_ips[:50]}
                try:
                    for fut in as_completed(futs, timeout=30):
                        ip, name = fut.result()
                        if name:
                            results[ip] = name
                except TimeoutError:
                    print("[HomeNet] DNS resolution timed out for some wired devices")
        except Exception as e:
            print(f"[HomeNet] DNS resolution error: {e}")

    # Phase 2: NetBIOS for wired devices that DNS missed
    wired_unresolved = [ip for ip in wired_ips if ip not in results]
    if wired_unresolved:
        try:
            with ThreadPoolExecutor(max_workers=min(len(wired_unresolved), 10)) as pool:
                futs = {pool.submit(_nbt_resolve_ip, ip): ip for ip in wired_unresolved[:20]}
                try:
                    for fut in as_completed(futs, timeout=60):
                        ip, name = fut.result()
                        if name:
                            results[ip] = name
                except TimeoutError:
                    print("[HomeNet] NetBIOS resolution timed out for some wired devices")
        except Exception as e:
            print(f"[HomeNet] NetBIOS resolution error: {e}")

    # Phase 3: For 10.x (wireless/Orbi) devices, hostnames come from Orbi SOAP API
    # (populated during scan via _merge_device_data). DNS won't work for 10.x because
    # they're behind Orbi NAT. Only try NetBIOS if Wi-Fi is connected to Orbi network.
    if wireless_ips:
        # Quick check: can we reach the Orbi router? (TCP 443 — its SOAP/web UI)
        can_reach = False
        try:
            with socket.create_connection(("10.0.0.1", 443), timeout=1.5):
                can_reach = True
        except (OSError, TimeoutError):
            pass

        if not can_reach:
            print(
                "[HomeNet] Wi-Fi not connected to Orbi — "
                "skipping 10.x name resolution. "
                "Connect Wi-Fi to resolve wireless device names."
            )
        else:
            try:
                with ThreadPoolExecutor(max_workers=min(len(wireless_ips), 10)) as pool:
                    futs = {pool.submit(_nbt_resolve_ip, ip): ip for ip in wireless_ips[:30]}
                    try:
                        for fut in as_completed(futs, timeout=60):
                            ip, name = fut.result()
                            if name:
                                results[ip] = name
                    except TimeoutError:
                        print("[HomeNet] Name resolution timed out for some wireless devices")
            except Exception as e:
                print(f"[HomeNet] Wireless name resolution error: {e}")

    return results


def _auto_categorize(vendor: str, hostname: str, device_type: str, device_os: str) -> str:
    """Auto-assign a category based on vendor, hostname, and device metadata."""
    # Explicit category from router data
    if device_type:
        dt_lower = device_type.lower()
        if dt_lower in ("phone", "smartphone", "mobile"):
            return "Phone"
        if dt_lower in ("computer", "pc", "laptop", "desktop"):
            return "Computer"
        if dt_lower in ("tv", "stb", "media", "streaming"):
            return "TV"
        if dt_lower in ("printer",):
            return "Printer"
        if dt_lower in ("tablet", "ipad"):
            return "Phone"
        if dt_lower in ("gaming", "console", "game console"):
            return "Other"

    # Category from OS
    if device_os:
        os_lower = device_os.lower()
        if "ios" in os_lower or "android" in os_lower:
            return "Phone"
        if "windows" in os_lower or "macos" in os_lower or "linux" in os_lower:
            return "Computer"

    # Category from vendor (exact match on the curated map first, then
    # substring-match against IEEE's long-form vendor names -- the map's
    # short keys like "Amazon" won't equal IEEE's "Amazon Technologies
    # Inc." so we fall through to the substring patterns for coverage).
    if vendor in _VENDOR_CATEGORY_MAP:
        return _VENDOR_CATEGORY_MAP[vendor]
    substr_cat = _categorise_by_vendor_substring(vendor)
    if substr_cat:
        return substr_cat

    # Category from hostname patterns
    if hostname:
        hn = hostname.lower()
        if any(k in hn for k in ("printer", "brw", "hp", "epson", "canon")):
            return "Printer"
        if any(k in hn for k in ("roku", "firestick", "chromecast", "appletv", "tv")):
            return "TV"
        if any(k in hn for k in ("iphone", "ipad", "galaxy", "pixel", "android")):
            return "Phone"
        if any(k in hn for k in ("echo", "alexa", "nest", "ring", "smartthings")):
            return "IoT"
        if any(k in hn for k in ("-pc", "desktop", "laptop", "macbook", "surface")):
            return "Computer"
        if any(k in hn for k in ("nas", "synology", "qnap", "readynas")):
            return "Storage"

    return ""


# How recent a peer MAC at the same IP must have been seen for the
# whole group to inherit active=True. 15 minutes matches the tray's
# standard polling cadence; longer windows leak across genuine offline
# transitions, shorter windows miss slower aggregation modes.
_IP_ACTIVE_ROLLUP_WINDOW_S = 15 * 60


def _rollup_active_by_ip(inventory: dict) -> None:
    """Treat multiple MACs at the same IP as one logical device for
    active-status reporting (backlog #10 third hotfix, 2026-04-23).

    Link-aggregated NICs (LACP, balance-alb, balance-tlb, active-backup)
    present multiple physical MACs sharing one IP. Our ARP-based scanner
    only sees the MAC that wins the bond's per-destination hash at any
    moment, so the other NICs in the bundle falsely appear as offline in
    the Home Network table -- even though they are physically connected
    and actively forwarding traffic.

    Rule: if ANY MAC at a given IP was seen within the last
    ``_IP_ACTIVE_ROLLUP_WINDOW_S`` seconds, every MAC at that IP
    inherits ``active=True``. Loopback, empty IPs, and link-local
    addresses are excluded so a stale entry at 0.0.0.0 can't
    accidentally activate a populated row at a real IP.

    Mutates ``inventory`` in place. Preserves each MAC's own
    ``last_seen`` timestamp so power users can still distinguish which
    NIC was the most recent hash winner.
    """
    now = datetime.now(timezone.utc)
    by_ip: dict[str, list[dict]] = {}
    for _mac, dev in inventory.get("devices", {}).items():
        ip = (dev.get("ip") or "").strip()
        # "0.0.0.0" is a catch-all for devices with no real IP; skipping it
        # here prevents stale entries at the placeholder from activating
        # real entries. Link-local 169.254.x.x is APIPA -- also not a real
        # shared-device IP. noqa: S104 is fine here; these are values we
        # compare against, not addresses we're binding to.
        if not ip or ip == "0.0.0.0" or ip.startswith("169.254."):  # noqa: S104
            continue
        by_ip.setdefault(ip, []).append(dev)

    for _ip, group in by_ip.items():
        if len(group) < 2:
            continue  # single-MAC IPs use their own active flag unchanged
        any_recent = False
        for dev in group:
            try:
                ls = datetime.fromisoformat(dev.get("last_seen", ""))
                if (now - ls).total_seconds() <= _IP_ACTIVE_ROLLUP_WINDOW_S:
                    any_recent = True
                    break
            except (ValueError, TypeError):
                continue
        if any_recent:
            for dev in group:
                dev["active"] = True


def _enrich_device_names(inventory: dict) -> dict:
    """
    Enrich device inventory with resolved names and auto-categories.
    Called after scan to fill in missing names.
    """
    # Phase A: Refresh vendor for any inventory entry currently marked
    # "Unknown" or empty (backlog #10 second hotfix, 2026-04-23). The
    # scan merge only calls _mac_vendor() for devices seen in the
    # current ARP/router responses -- but offline-for-days devices
    # stay in the inventory with whatever vendor they had at the time
    # of their last scan. When the IEEE OUI lookup was introduced,
    # these stale entries kept their old "Unknown" value even though
    # the new code would resolve them. This pass backfills them.
    for _mac, dev in inventory["devices"].items():
        current = (dev.get("vendor") or "").strip()
        if current in ("", "Unknown"):
            new_vendor = _mac_vendor(dev.get("mac", ""))
            if new_vendor and new_vendor != "Unknown":
                dev["vendor"] = new_vendor

    devices_needing_names = []
    for _mac, dev in inventory["devices"].items():
        hostname = dev.get("hostname", "")
        if not hostname or hostname == dev.get("ip", "") or hostname.lower() == "unknown":
            devices_needing_names.append(dev)

    # Batch resolve names
    if devices_needing_names:
        resolved = _resolve_names_batch(devices_needing_names)
        for _mac, dev in inventory["devices"].items():
            ip = dev.get("ip", "")
            if ip in resolved and resolved[ip]:
                # Only update if no existing good hostname
                existing = dev.get("hostname", "")
                if not existing or existing == ip or existing.lower() == "unknown":
                    dev["hostname"] = resolved[ip]

    # Auto-categorize all devices that don't have a user-set category
    for _mac, dev in inventory["devices"].items():
        if not dev.get("category"):
            auto_cat = _auto_categorize(
                dev.get("vendor", ""),
                dev.get("hostname", ""),
                dev.get("device_type", ""),
                dev.get("device_os", ""),
            )
            if auto_cat:
                dev["category"] = auto_cat

    # Roll up active-status across NICs sharing an IP so link-aggregated
    # devices (LACP / balance-alb / active-backup) show a consistent
    # "green dot" across every registered MAC -- see _rollup_active_by_ip
    # docstring for the full rationale.
    _rollup_active_by_ip(inventory)

    return inventory


# ── ARP scan for local subnet discovery ──────────────────────────────────────


def _arp_scan() -> list:
    """Run ``arp -a`` directly and parse the output in Python.

    Returns a list of dicts with keys: Interface, IP, MAC, Type.
    """
    try:
        r = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        results = []
        current_iface = ""
        for line in r.stdout.splitlines():
            m_iface = re.match(r"Interface:\s*([\d.]+)", line)
            if m_iface:
                current_iface = m_iface.group(1)
                continue
            m_entry = re.match(r"\s*([\d.]+)\s+([\w-]{17})\s+(\w+)", line)
            if m_entry:
                results.append(
                    {
                        "Interface": current_iface,
                        "IP": m_entry.group(1),
                        "MAC": m_entry.group(2).upper().replace("-", ":"),
                        "Type": m_entry.group(3),
                    }
                )
        return results
    except Exception as e:
        print(f"[HomeNet] ARP scan error: {e}")
        return []


# ── Unified device inventory ─────────────────────────────────────────────────


def _load_homenet_inventory() -> dict:
    """Load persisted device inventory."""
    try:
        if os.path.exists(HOMENET_INVENTORY_FILE):
            with open(HOMENET_INVENTORY_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"devices": {}, "last_scan": None}


def _save_homenet_inventory(inventory: dict) -> None:
    """Persist device inventory to disk."""
    with _homenet_lock:
        try:
            with open(HOMENET_INVENTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(inventory, f, indent=2)
        except Exception as e:
            print(f"[HomeNet] save error: {e}")


def _merge_device_data(inventory: dict, source: str, devices: list) -> dict:
    """Merge discovered devices into inventory, preserving user labels."""
    for dev in devices:
        mac = dev.get("mac", dev.get("MAC", "")).upper().replace("-", ":")
        if not mac or mac == "FF:FF:FF:FF:FF:FF":
            continue

        existing = inventory["devices"].get(mac, {})
        ip = dev.get("ip", dev.get("IP", ""))
        name = dev.get("name", dev.get("Name", "")) or existing.get("hostname", "")

        inventory["devices"][mac] = {
            "mac": mac,
            "ip": ip,
            "hostname": name,
            "vendor": _mac_vendor(mac),
            "network": "wireless" if ip.startswith("10.") else "wired",
            "source": source,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            # Preserve user-set fields
            "friendly_name": existing.get("friendly_name", ""),
            "category": existing.get("category", ""),
            "location": existing.get("location", ""),
            "notes": existing.get("notes", ""),
            # Merge extra fields from routers
            "connection_type": dev.get("connection_type", existing.get("connection_type", "")),
            "signal_strength": dev.get("signal_strength", existing.get("signal_strength", "")),
            "link_rate": dev.get("link_rate", existing.get("link_rate", "")),
            "device_type": dev.get("device_type", dev.get("dev_class", existing.get("device_type", ""))),
            "device_os": dev.get("device_os", existing.get("device_os", "")),
            "device_model": dev.get("device_model", existing.get("device_model", "")),
            "device_brand": dev.get("device_brand", existing.get("device_brand", "")),
            "ssid": dev.get("ssid", existing.get("ssid", "")),
            # ConnAPMAC = which Orbi node (router or satellite) the wireless
            # client is associated with. Used by /api/homenet/topology (#9)
            # to draw the device under the right satellite. Empty for wired.
            "conn_ap_mac": dev.get("conn_ap_mac", existing.get("conn_ap_mac", "")),
            # User-set classification for wired devices that aren't on the
            # TP-Link MAC table. Values: "moca" (downstream of a MoCA bridge,
            # comes in via coax), "verizon_lan" (plugged direct into the
            # Verizon's LAN ports), "switch" (force into the switch column
            # even without SNMP confirmation), or "" (unknown -- defaults to
            # Verizon LAN bucket in the topology). Preserves existing user
            # choice across scans -- the merge never overwrites it from a
            # discovery source.
            "wired_via": existing.get("wired_via", ""),
            # MAC of the parent MoCA bridge this device sits behind, when
            # the user has set it via the device-edit modal. Used by the
            # topology builder to group devices under their bridge in the
            # MoCA Bridges column (instead of dumping them all into a flat
            # via_moca list). Empty for devices not behind any bridge.
            # MoCA bridges are transparent (no IP, no per-port info) so
            # this can only ever be set by user attestation -- there's no
            # auto-discovery path that could populate it.
            "behind_moca_bridge": existing.get("behind_moca_bridge", ""),
            "active": dev.get("activity", 1) == 1 if "activity" in dev else True,
        }

    inventory["last_scan"] = datetime.now(timezone.utc).isoformat()
    return inventory


def _wifi_ensure_orbi_connected() -> tuple:
    """
    Ensure Wi-Fi is connected to the Orbi network for 10.x device access.
    Returns (was_connected: bool, wifi_was_enabled: bool, original_ssid: str).
    If Wi-Fi is already on a 10.x network, returns immediately.
    If Wi-Fi is off or on a different network, enables it and tries to connect
    to a saved Orbi Wi-Fi profile.
    """
    try:
        # Check current Wi-Fi state
        r = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-Command",
                (
                    "$wifi = Get-NetAdapter -Name 'Wi-Fi' -ErrorAction SilentlyContinue; "
                    "if (-not $wifi) { Write-Host 'NO_ADAPTER'; exit } "
                    "$status = $wifi.Status; "
                    "$ip = (Get-NetIPAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 "
                    "-ErrorAction SilentlyContinue).IPAddress; "
                    "$profile = (netsh wlan show interfaces | "
                    "Select-String 'SSID\\s+:' | Select-Object -First 1); "
                    "$ssid = if ($profile) { "
                    "($profile -replace '.*SSID\\s+:\\s*','').Trim() } else { '' }; "
                    'Write-Host "$status|$ip|$ssid"'
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        out = r.stdout.strip()
        if out == "NO_ADAPTER":
            return (False, False, "")

        parts = out.split("|", 2)
        status = parts[0] if len(parts) > 0 else ""
        ip = parts[1] if len(parts) > 1 else ""
        ssid = parts[2] if len(parts) > 2 else ""

        # Already connected to 10.x network — good
        if ip.startswith("10."):
            return (True, True, ssid)

        # Wi-Fi is up but not on 10.x, or Wi-Fi is disabled
        # Try to enable adapter if needed, then connect to Orbi SSID
        original_was_up = status == "Up"

        if not original_was_up:
            subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-Command",
                    "Enable-NetAdapter -Name 'Wi-Fi' -Confirm:$false",
                ],
                capture_output=True,
                timeout=10,
            )
            import time

            time.sleep(3)

        # Get the Orbi SSID from credentials (stored as extra field)
        # or try all saved Wi-Fi profiles to find one that gives a 10.x IP
        orbi_ssid = _get_orbi_ssid()
        if orbi_ssid:
            # Try to connect to the known Orbi SSID
            subprocess.run(
                ["netsh", "wlan", "connect", f"name={orbi_ssid}"],
                capture_output=True,
                timeout=10,
            )
            import time

            time.sleep(5)

            # Check if we got a 10.x IP
            r2 = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-Command",
                    (
                        "$ip = (Get-NetIPAddress -InterfaceAlias 'Wi-Fi' "
                        "-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress; "
                        "Write-Host $ip"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            new_ip = r2.stdout.strip()
            if new_ip.startswith("10."):
                print(f"[HomeNet] Connected to Orbi Wi-Fi ({orbi_ssid})")
                return (True, original_was_up, ssid)

        # Auto-connect didn't work — check if we got 10.x from auto-connect
        r3 = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-Command",
                (
                    "$ip = (Get-NetIPAddress -InterfaceAlias 'Wi-Fi' "
                    "-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress; "
                    "Write-Host $ip"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        check_ip = r3.stdout.strip()
        if check_ip.startswith("10."):
            return (True, original_was_up, ssid)

        return (False, original_was_up, ssid)

    except Exception as e:
        print(f"[HomeNet] Wi-Fi check error: {e}")
        return (False, True, "")


def _get_orbi_ssid() -> str:
    """Get the Orbi Wi-Fi SSID from stored config or saved Wi-Fi profiles."""
    # Check if user stored an SSID in the Orbi credential notes
    try:
        inv = _load_homenet_inventory()
        orbi_ssid = inv.get("orbi_ssid", "")
        if orbi_ssid:
            return orbi_ssid
    except Exception:
        pass

    # Fall back: look for saved Wi-Fi profiles that might be Orbi
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-Command",
                (
                    "$profiles = netsh wlan show profiles | "
                    "Select-String 'All User Profile\\s+:' | "
                    "ForEach-Object { ($_ -replace '.*:\\s*','').Trim() }; "
                    "$profiles -join '|'"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        profiles = [p.strip() for p in r.stdout.strip().split("|") if p.strip()]
        if len(profiles) == 1:
            return profiles[0]  # Only one profile — likely the Orbi
    except Exception:
        pass

    return ""


def _wifi_restore(was_enabled: bool):
    """Restore Wi-Fi to its original state if we enabled it."""
    if not was_enabled:
        try:
            subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-Command",
                    "Disable-NetAdapter -Name 'Wi-Fi' -Confirm:$false",
                ],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass


def homenet_full_scan() -> dict:
    """
    Run a full network scan: ARP + Verizon + Orbi.
    If Wi-Fi is not connected to Orbi, temporarily enables it to scan wireless devices.
    Returns merged inventory.
    """
    inventory = _load_homenet_inventory()
    errors = []

    # Check if Wi-Fi can reach Orbi (10.x) network
    wifi_connected, wifi_was_enabled, _orig_ssid = _wifi_ensure_orbi_connected()

    try:
        # 1. ARP scan (always works on local subnets)
        arp_devices = _arp_scan()
        arp_as_devices = [
            {"mac": d.get("MAC", ""), "ip": d.get("IP", ""), "name": ""}
            for d in arp_devices
            if d.get("Type", "").lower() == "dynamic"
        ]
        inventory = _merge_device_data(inventory, "arp", arp_as_devices)

        # 2. Verizon CR1000A
        verizon = _verizon_get_devices()
        if verizon.get("ok"):
            known = verizon.get("known_devices", {})
            if isinstance(known, dict):
                known = known.get("known_devices", [])
            if isinstance(known, list):
                vz_devices = [
                    {
                        "mac": d.get("mac", ""),
                        "ip": d.get("ip", ""),
                        "name": d.get("hostname", d.get("device_name", "")),
                        "dev_class": d.get("dev_class", ""),
                        "device_os": d.get("device_os", ""),
                        "activity": d.get("activity", 0),
                    }
                    for d in known
                ]
                inventory = _merge_device_data(inventory, "verizon", vz_devices)
        elif "error" in verizon:
            errors.append(f"Verizon: {verizon['error']}")

        # 3. Orbi (needs Wi-Fi connected to 10.x network)
        if wifi_connected:
            orbi = _orbi_get_devices()
            if orbi.get("ok"):
                inventory = _merge_device_data(inventory, "orbi", orbi.get("devices", []))
            elif "error" in orbi:
                errors.append(f"Orbi: {orbi['error']}")
        else:
            errors.append(
                "Orbi: Wi-Fi not connected to Orbi network — "
                "wireless device names unavailable. "
                "Enable Wi-Fi and connect to your Orbi network, then re-scan."
            )

        # 4. Enrich with name resolution + auto-categorization
        inventory = _enrich_device_names(inventory)

    finally:
        # Restore Wi-Fi if we changed it
        _wifi_restore(wifi_was_enabled)

    _save_homenet_inventory(inventory)

    return {
        "ok": True,
        "device_count": len(inventory["devices"]),
        "last_scan": inventory["last_scan"],
        "errors": errors,
        "devices": list(inventory["devices"].values()),
    }


def homenet_get_inventory() -> dict:
    """Return current inventory without scanning."""
    inventory = _load_homenet_inventory()
    return {
        "ok": True,
        "device_count": len(inventory["devices"]),
        "last_scan": inventory.get("last_scan"),
        "devices": list(inventory["devices"].values()),
    }


# ── Flask Routes ─────────────────────────────────────────────────────────────


@homenet_bp.route("/api/homenet/credentials")
def homenet_credentials():
    """List configured device credentials (passwords masked)."""
    return jsonify(_list_homenet_creds())


@homenet_bp.route("/api/homenet/credentials/save", methods=["POST"])
def homenet_credentials_save():
    """Save credentials for a device."""
    body = request.get_json() or {}
    device_key = re.sub(r"[^a-z0-9_]", "", str(body.get("device_key", ""))).strip()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    if not device_key or not username or not password:
        return jsonify({"ok": False, "message": "device_key, username, and password required"}), 400
    ok = _set_homenet_cred(device_key, username, password)

    # If saving Orbi creds, also save the Wi-Fi SSID for auto-connect
    if device_key == "orbi":
        orbi_ssid = str(body.get("orbi_ssid", "")).strip()
        if orbi_ssid:
            try:
                inv = _load_homenet_inventory()
                inv["orbi_ssid"] = orbi_ssid
                _save_homenet_inventory(inv)
            except Exception:
                pass

    return jsonify({"ok": ok, "message": "Credentials saved" if ok else "Failed to save"})


@homenet_bp.route("/api/homenet/credentials/delete", methods=["POST"])
def homenet_credentials_delete():
    """Delete stored credentials for a device."""
    body = request.get_json() or {}
    device_key = re.sub(r"[^a-z0-9_]", "", str(body.get("device_key", ""))).strip()
    if not device_key:
        return jsonify({"ok": False, "message": "device_key required"}), 400
    ok = _delete_homenet_cred(device_key)
    return jsonify({"ok": ok, "message": "Credentials deleted" if ok else "Failed to delete"})


@homenet_bp.route("/api/homenet/credentials/test", methods=["POST"])
def homenet_credentials_test():
    """Test connection to a device with stored credentials."""
    body = request.get_json() or {}
    device_key = re.sub(r"[^a-z0-9_]", "", str(body.get("device_key", ""))).strip()
    if device_key == "verizon":
        result = _verizon_get_devices()
        if result.get("ok"):
            count = len(result.get("known_devices", {}).get("known_devices", []))
            return jsonify({"ok": True, "message": f"Connected! Found {count} devices."})
        return jsonify({"ok": False, "message": result.get("error", "Connection failed")})
    elif device_key == "orbi":
        result = _orbi_get_devices()
        if result.get("ok"):
            return jsonify({"ok": True, "message": f"Connected! Found {len(result.get('devices', []))} devices."})
        return jsonify({"ok": False, "message": result.get("error", "Connection failed")})
    elif device_key == "tplink_switch":
        result = _tplink_get_data()
        if result.get("ok"):
            up = sum(1 for p in result.get("ports", []) if p["status"] == "up")
            total = len(result.get("ports", []))
            return jsonify(
                {
                    "ok": True,
                    "message": f"Connected! {up}/{total} ports up, {len(result.get('mac_table', []))} MACs learned.",
                }
            )
        return jsonify({"ok": False, "message": result.get("error", "Connection failed")})
    return jsonify({"ok": False, "message": f"Unknown device: {device_key}"}), 400


@homenet_bp.route("/api/homenet/scan", methods=["POST"])
def homenet_scan():
    """Run full network scan (ARP + routers)."""
    return jsonify(homenet_full_scan())


@homenet_bp.route("/api/homenet/scan/light", methods=["POST"])
def homenet_scan_light():
    """Light scan: ARP only — fast (~2s), updates online/offline status."""
    inventory = _load_homenet_inventory()
    arp_devices = _arp_scan()
    # Build set of currently-visible MACs
    live_macs = set()
    for d in arp_devices:
        mac = d.get("MAC", "").upper().replace("-", ":")
        if mac and d.get("Type", "").lower() == "dynamic":
            live_macs.add(mac)
            # Update IP if device already known
            if mac in inventory["devices"]:
                inventory["devices"][mac]["ip"] = d.get("IP", inventory["devices"][mac].get("ip", ""))
                inventory["devices"][mac]["last_seen"] = datetime.now(timezone.utc).isoformat()
                inventory["devices"][mac]["active"] = True
            else:
                # New device from ARP
                ip = d.get("IP", "")
                inventory["devices"][mac] = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": "",
                    "vendor": _mac_vendor(mac),
                    "network": "wireless" if ip.startswith("10.") else "wired",
                    "source": "arp",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "friendly_name": "",
                    "category": "",
                    "location": "",
                    "notes": "",
                    "connection_type": "",
                    "signal_strength": "",
                    "link_rate": "",
                    "device_type": "",
                    "device_os": "",
                    "active": True,
                }

    # Mark devices not seen in ARP as potentially offline
    # Only mark inactive if they were on a subnet we can ARP (same interface)
    for mac, dev in inventory["devices"].items():
        if mac not in live_macs:
            dev["active"] = False

    # Re-apply the IP-aggregation rollup so link-aggregated NICs stay
    # green even when only one bond member wins the ARP hash this minute.
    # Without this, the light scan stomps the full scan's rollup every
    # polling cycle and the QNAP's bonded NICs flicker grey after 60 s.
    _rollup_active_by_ip(inventory)

    inventory["last_scan"] = datetime.now(timezone.utc).isoformat()
    _save_homenet_inventory(inventory)

    return jsonify(
        {
            "ok": True,
            "device_count": len(inventory["devices"]),
            "last_scan": inventory["last_scan"],
            "devices": list(inventory["devices"].values()),
        }
    )


@homenet_bp.route("/api/homenet/inventory")
def homenet_inventory():
    """Get current device inventory (no scan)."""
    return jsonify(homenet_get_inventory())


@homenet_bp.route("/api/homenet/resolve-names", methods=["POST"])
def homenet_resolve_names():
    """Run name resolution on all devices with missing names."""
    inventory = _load_homenet_inventory()
    before = sum(1 for d in inventory["devices"].values() if d.get("hostname"))
    inventory = _enrich_device_names(inventory)
    after = sum(1 for d in inventory["devices"].values() if d.get("hostname"))
    _save_homenet_inventory(inventory)
    return jsonify(
        {
            "ok": True,
            "resolved": after - before,
            "total_named": after,
            "total_devices": len(inventory["devices"]),
            "devices": list(inventory["devices"].values()),
        }
    )


@homenet_bp.route("/api/homenet/device/update", methods=["POST"])
def homenet_device_update():
    """Update user-editable fields for a device (friendly_name, category, location, notes)."""
    body = request.get_json() or {}
    mac = str(body.get("mac", "")).upper().replace("-", ":")
    if not mac:
        return jsonify({"ok": False, "message": "MAC address required"}), 400

    inventory = _load_homenet_inventory()
    if mac not in inventory["devices"]:
        return jsonify({"ok": False, "message": f"Device {mac} not in inventory"}), 404

    for field in ("friendly_name", "category", "location", "notes"):
        if field in body:
            inventory["devices"][mac][field] = str(body[field])
    # wired_via is a constrained value -- whitelist to prevent garbage values
    # leaking into the topology classifier and creating ghost columns.
    if "wired_via" in body:
        val = str(body["wired_via"]).lower().strip()
        # "moca_bridge" = the device IS a MoCA bridge (override vendor
        # detection -- e.g. when the vendor name doesn't match _MOCA_
        # VENDOR_PATTERNS but the user knows it's a coax-to-Ethernet
        # bridge, like a Verizon-branded extender or a third-party box
        # whose OUI hasn't been catalogued yet).
        if val in ("moca", "moca_bridge", "verizon_lan", "switch", ""):
            inventory["devices"][mac]["wired_via"] = val
    # Parent MoCA bridge -- MAC of the bridge this device sits behind.
    # Validates the format (or accepts empty to clear the link). We
    # don't enforce that the MAC is actually in the inventory or marked
    # as a bridge -- that would race against scan-induced inventory
    # changes; the topology builder skips dangling pointers gracefully.
    if "behind_moca_bridge" in body:
        val = str(body["behind_moca_bridge"]).upper().replace("-", ":").strip()
        if val == "" or re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", val):
            inventory["devices"][mac]["behind_moca_bridge"] = val

    _save_homenet_inventory(inventory)
    return jsonify({"ok": True, "message": "Device updated"})


@homenet_bp.route("/api/homenet/device/add-manual", methods=["POST"])
def homenet_device_add_manual():
    """Manually add a device by MAC -- for transparent network gear that
    LAN scans (ARP, mDNS, router APIs) can't see.

    Use case discovered 2026-04-25: Verizon-branded transparent MoCA
    bridges (Askey OUI 88:DE:7C) have no IP and never appear in ARP, so
    the normal scan flow misses them entirely. The user knows the bridge
    exists (it's in their living room) but the diagram can't show it
    until the inventory has an entry.

    Body shape:
        {"mac": "AA:BB:CC:DD:EE:FF",
         "friendly_name": "Living Room MoCA",   (optional)
         "wired_via": "moca_bridge",            (optional, defaults to "moca_bridge"
                                                 since manual-add is the use case)
         "category": "Network",                  (optional, defaults to "Network")
         "notes": "..."}                         (optional)

    The MAC is sanity-checked, the OUI vendor lookup runs automatically,
    and the entry is marked source="manual" so future scans never
    overwrite the user's metadata.
    """
    body = request.get_json(silent=True) or {}
    mac = str(body.get("mac", "")).upper().replace("-", ":").strip()

    # Basic MAC-format validation: 6 hex pairs separated by colons.
    if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", mac):
        return jsonify({"ok": False, "message": f"Invalid MAC format: {mac!r}"}), 400

    inventory = _load_homenet_inventory()
    if mac in inventory["devices"]:
        return (
            jsonify(
                {"ok": False, "message": f"Device {mac} already in inventory -- use /api/homenet/device/update instead"}
            ),
            409,
        )

    wired_via = (body.get("wired_via") or "moca_bridge").lower()
    if wired_via not in ("moca", "moca_bridge", "verizon_lan", "switch", ""):
        wired_via = "moca_bridge"  # default for the common manual-add case

    inventory["devices"][mac] = {
        "mac": mac,
        "ip": "",
        "hostname": str(body.get("friendly_name", "")) or "(transparent device)",
        "vendor": _mac_vendor(mac),
        "network": "wired",
        "source": "manual",
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "friendly_name": str(body.get("friendly_name", "")),
        "category": str(body.get("category", "Network")),
        "location": str(body.get("location", "")),
        "notes": str(body.get("notes", ""))
        or "Manually added by user (likely a transparent MoCA bridge or other LAN-invisible device).",
        "connection_type": "",
        "signal_strength": "",
        "link_rate": "",
        "device_type": "",
        "device_os": "",
        "device_model": "",
        "device_brand": "",
        "ssid": "",
        "conn_ap_mac": "",
        "wired_via": wired_via,
        "active": True,
    }
    _save_homenet_inventory(inventory)
    return jsonify({"ok": True, "message": "Device added", "device": inventory["devices"][mac]})


@homenet_bp.route("/api/homenet/switch")
def homenet_switch_data():
    """Get TP-Link switch port status, traffic stats, and MAC table."""
    result = _tplink_get_data()
    return jsonify(result)


# ── Network topology (#9) ───────────────────────────────────────────────────


# Well-known infrastructure MACs / IPs for the Williams home network. Centralised
# here so the topology builder can label them with friendly names instead of raw
# hex. If the user's Orbi satellite MACs are unknown they'll still appear in the
# diagram as "Orbi satellite (xx:xx:...)" -- only the labels are missing.
_INFRA_LABELS: dict[str, dict] = {
    # Verizon CR1000A is the gateway / DHCP server. The MAC isn't pinned because
    # the Verizon API returns it dynamically; we identify the router by IP.
    "192.168.1.1": {"name": "Verizon CR1000A", "type": "router", "icon": "🛜"},
    # TP-Link TL-SG2218 -- the wired-edge switch. Pinned by MAC since its IP is
    # whatever the user configured.
    "DC:62:79:F3:52:5C": {"name": "TP-Link TL-SG2218 (Switch)", "type": "switch", "icon": "🔀"},
    # Orbi router (RBRE960 base). Pinned by IP because the MAC is per-unit.
    "10.0.0.1": {"name": "Orbi RBRE960 (Router)", "type": "ap", "icon": "📡"},
}


def _is_infrastructure_mac(mac: str) -> bool:
    """True if this MAC belongs to a known router / switch / AP."""
    return mac.upper() in _INFRA_LABELS


# Vendors that ship MoCA-over-coax Ethernet bridges. When a device with one
# of these vendor-name substrings is in the inventory, it's almost certainly
# a MoCA endpoint -- one of the boxes the user has wired into a coax run to
# turn it into Ethernet. We render those as their own "MoCA / Verizon-direct"
# column so users immediately understand why their devices aren't on the
# TP-Link MAC table (they never traverse the switch -- they go device → MoCA
# bridge → coax → Verizon's built-in MoCA bridge → Verizon LAN).
#
# Lowercase substring match against the IEEE / curated vendor name. Order
# doesn't matter -- any match counts.
_MOCA_VENDOR_PATTERNS: tuple[str, ...] = (
    "actiontec",  # Actiontec ECB6200, MoCA Network Adapter MM1000
    "gocoax",  # GoCoax MA2500D
    "motorola mobility",  # MM1000 OEM
    "screenbeam",  # ScreenBeam (Actiontec spinoff) MoCA adapters
    "hitron",  # Hitron Coda MoCA bridges
    "westell",  # Verizon-branded older MoCA extenders
    # Verizon FiOS Set-Top Boxes are MoCA endpoints (the VMS4100/VMS1100
    # series uses MoCA-over-coax for everything: video, guide updates, IP).
    # Both Arris and its acquirer Commscope ship these. We intentionally
    # match the broad vendor name -- in the FiOS context essentially every
    # Commscope/Arris device on the LAN is going to be a MoCA endpoint.
    "commscope",  # Verizon FiOS STBs (VMS4100ATV etc.) -- MoCA over coax
    "arris",  # pre-Commscope STB OEM
    # Askey Computer Corp is a Taiwan-based ODM that builds Verizon-branded
    # MoCA bridges + FiOS Network Extenders. Discovered 2026-04-25 when a
    # user reported their 2nd Verizon MoCA wasn't auto-detected -- it has
    # OUI 88:DE:7C which IEEE resolves to "ASKEY COMPUTER CORP". Many
    # transparent MoCA bridges (no IP of their own, just relay coax<->
    # Ethernet) ship with Askey hardware.
    "askey",
)


# Hostname substrings that identify infrastructure devices the inventory
# may have multiple MAC entries for (e.g. the Orbi has separate WAN-side
# and LAN-side MACs that ARP scans pick up as two different devices).
# Anything whose hostname matches lands in the infrastructure set and is
# excluded from "via_verizon_or_moca" / "unmapped" -- it's rendered as
# its own infra tier-2 node instead.
_INFRA_HOSTNAME_PATTERNS: tuple[str, ...] = (
    "rbre",  # Orbi RBRE960 -- WAN-side MAC has hostname like "RBRE960.mynetworksettings.com"
    "cr1000",  # Verizon CR1000A / CR1000B
    "tl-sg",  # TP-Link TL-SG2218
)


def _is_infra_by_hostname(device: dict) -> bool:
    """True if the device's hostname matches a known infra-device pattern.
    Catches the case where ARP picks up the Orbi's WAN-side MAC at a
    192.x address even though its primary LAN-side MAC is at 10.0.0.1."""
    host = (device.get("hostname") or "").lower()
    if not host:
        return False
    return any(p in host for p in _INFRA_HOSTNAME_PATTERNS)


def _is_moca_bridge(device: dict) -> bool:
    """True if this device is a MoCA-over-coax Ethernet bridge.

    Resolution order (first match wins):
      1. **Explicit "is a bridge"** -- ``wired_via == "moca_bridge"``
         set by the user via the device-edit modal. Always wins.
      2. **Explicit "NOT a bridge"** -- ``wired_via`` set to anything
         else specific ("moca", "verizon_lan", "switch"). The user has
         deliberately classified the device, so vendor-pattern auto-
         detection MUST NOT override their choice. Bug 2026-04-25:
         user reported "VMS4100ATV is a Verizon Set-Top Box (endpoint,
         not a bridge)" but the Commscope vendor pattern kept tagging
         it as a bridge even after they set wired_via=moca. Fixed
         here -- any non-empty wired_via value is treated as the
         user's final word on bridge-vs-endpoint classification.
      3. **No user attestation** (wired_via empty) -- fall back to
         vendor-name pattern match against _MOCA_VENDOR_PATTERNS.
         Auto-detection so the user doesn't have to tag every
         well-known device manually on a fresh setup.
    """
    wv = (device.get("wired_via") or "").lower()
    if wv == "moca_bridge":
        return True
    if wv in ("moca", "verizon_lan", "switch"):
        return False
    vendor = (device.get("vendor") or "").lower()
    if not vendor:
        return False
    return any(p in vendor for p in _MOCA_VENDOR_PATTERNS)


def _orbi_get_satellites() -> dict:
    """Query the Orbi for its satellite list with user-set device names.

    The user labels each satellite in the Orbi web UI ("Upstairs",
    "Downstairs", etc.) and the router stores those labels. The SOAP
    action ``GetAllNewSatellites`` (NETGEAR-ROUTER:service:DeviceInfo:1)
    returns them via the ``DeviceName`` element per satellite. Some
    Orbi firmware versions also surface this via ``GetCurrentSetting``;
    we try the documented SOAP action first.

    Returns ``{"ok": True, "satellites": [{"mac": "...", "name": "...",
    "ip": "...", "model": "..."}, ...]}`` on success, or
    ``{"error": "..."}`` on failure. Failure is non-fatal -- callers
    fall back to the existing per-MAC labelling pipeline.
    """
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    user, pw = _get_homenet_cred("orbi")
    if not user or not pw:
        return {"error": "No Orbi credentials configured."}

    url = "https://10.0.0.1/soap/server_sa/"
    headers = {
        "SOAPAction": "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAllNewSatellites",
        "Content-Type": "text/xml; charset=utf-8",
    }
    soap_body = """<?xml version="1.0" encoding="UTF-8"?>
<v:Envelope xmlns:v="http://schemas.xmlsoap.org/soap/envelope/">
  <v:Header><SessionID>DEF456</SessionID></v:Header>
  <v:Body>
    <M1:GetAllNewSatellites xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1"/>
  </v:Body>
</v:Envelope>"""

    session = None
    try:
        session = requests.Session()
        session.verify = False
        r = session.post(url, data=soap_body, headers=headers, timeout=10, auth=(user, pw))
        if r.status_code != 200:
            return {"error": f"Orbi SOAP GetAllNewSatellites returned HTTP {r.status_code}"}
        return {"ok": True, "satellites": _parse_orbi_satellites(r.text)}
    except (requests.exceptions.RequestException, OSError) as e:
        return {"error": f"Orbi satellite query failed: {e}"}
    finally:
        if session is not None:
            session.close()


def _parse_orbi_satellites(xml_text: str) -> list:
    """Parse the SOAP response for GetAllNewSatellites into a list.

    Per-satellite XML shape varies by firmware; we read every common tag
    (DeviceName / Name, MAC, IP, ModelName / DeviceModel) and emit a
    uniform dict so the caller doesn't have to care which firmware
    revision shipped which fieldset.
    """
    out: list[dict] = []
    blocks = re.findall(r"<NewSatellite>(.*?)</NewSatellite>", xml_text, re.DOTALL)
    if not blocks:
        # Some firmware uses a different wrapper -- catch the common variants
        blocks = re.findall(r"<Satellite>(.*?)</Satellite>", xml_text, re.DOTALL)
    for block in blocks:

        def _tag(name, _block=block):
            m = re.search(rf"<{name}>(.*?)</{name}>", _block)
            return m.group(1).strip() if m else ""

        mac = (_tag("MAC") or _tag("Mac")).upper().replace("-", ":")
        if not mac:
            continue
        name = _tag("DeviceName") or _tag("Name") or _tag("FriendlyName")
        out.append(
            {
                "mac": mac,
                "name": name,
                "ip": _tag("IP") or _tag("Ip"),
                "model": _tag("ModelName") or _tag("DeviceModel") or "",
            }
        )
    return out


# Process-level cache for satellite names. The Orbi SOAP call is ~1-3s
# and the satellite list rarely changes (only when a user adds/renames
# a satellite via the Orbi web UI), so a 5-minute TTL is plenty. Stops
# every topology refresh from hitting the router.
_orbi_sat_cache: dict = {"ts": 0.0, "data": []}
_ORBI_SAT_TTL_S = 300.0


def _get_orbi_satellite_names_cached() -> dict[str, str]:
    """Return ``{mac_upper: friendly_name}`` for satellites the Orbi knows
    about. Cached for _ORBI_SAT_TTL_S seconds. Returns {} on any failure
    so callers can treat it as "no extra info available" without special-
    casing errors.
    """
    import time as _time

    now = _time.time()
    if (now - _orbi_sat_cache["ts"]) < _ORBI_SAT_TTL_S and _orbi_sat_cache["data"]:
        return dict(_orbi_sat_cache["data"])
    try:
        result = _orbi_get_satellites()
    except Exception:  # noqa: BLE001 -- best effort; never let this break topology
        return {}
    out: dict[str, str] = {}
    if isinstance(result, dict) and result.get("ok"):
        for s in result.get("satellites") or []:
            mac = (s.get("mac") or "").upper()
            name = (s.get("name") or "").strip()
            if mac and name:
                out[mac] = name
    # Cache even an empty result -- avoid hammering the router when the
    # SOAP action isn't supported on this firmware.
    _orbi_sat_cache["ts"] = now
    _orbi_sat_cache["data"] = list(out.items())
    return out


def _label_orbi_node(
    mac: str,
    devices_by_mac: dict | None = None,
    is_base: bool = False,
    sat_names_from_orbi: dict[str, str] | None = None,
) -> str:
    """Friendly label for an Orbi node MAC.

    Resolution order (first match wins):
      1. Hard-pinned _INFRA_LABELS entry (e.g. the Orbi base by IP)
      2. ``friendly_name`` set by the user via WinDesktopMgr's edit modal
      3. ``hostname`` if the inventory captured one
      4. ``sat_names_from_orbi[mac]`` -- the name the user set on the Orbi
         router itself ("Upstairs Orbi" / "Downstairs Orbi"). This is the
         "I already named this in the Orbi UI" path; we read it via SOAP
         so the topology automatically reflects what the user already set.
      5. ``is_base=True`` -> "Orbi RBRE960 (Base)" -- distinct from satellites
      6. Fallback: "Orbi satellite (XXXX)" using last 4 hex of MAC

    Bugs fixed 2026-04-25:
      - Base was rendered as "Orbi satellite (73E1)" because its MAC isn't
        in _INFRA_LABELS (only the IP is) and the fallback didn't know it
        was the base. Added ``is_base`` parameter.
      - Satellites the user already named in the Orbi UI weren't picked
        up because we never asked the Orbi for those names. Added a
        cached SOAP query (5 min TTL).
    """
    upper = mac.upper()
    if upper in _INFRA_LABELS:
        return _INFRA_LABELS[upper]["name"]
    if devices_by_mac:
        dev = devices_by_mac.get(upper) or {}
        friendly = (dev.get("friendly_name") or "").strip()
        if friendly:
            return friendly
        hostname = (dev.get("hostname") or "").strip()
        if hostname:
            return hostname.replace(".mynetworksettings.com", "")
    if sat_names_from_orbi:
        orbi_name = (sat_names_from_orbi.get(upper) or "").strip()
        if orbi_name:
            return orbi_name
    if is_base:
        return "Orbi RBRE960 (Base)"
    suffix = upper.replace(":", "")[-4:]
    return f"Orbi satellite ({suffix})"


def build_topology(inventory: dict | None = None, switch_data: dict | None = None) -> dict:
    """Join the device inventory + switch MAC table + Orbi satellite mapping
    into a hierarchical topology suitable for SVG rendering.

    The shape::

        {
            "ok": True,
            "router": {"id": "router", "name": "Verizon CR1000A", "ip": "192.168.1.1"},
            "switches": [
                {"id": "switch-DC:62:..", "name": "TP-Link TL-SG2218 (Switch)",
                 "ports": {1: [<mac>, ...], 2: [...], ...}}
            ],
            "aps": [
                {"id": "ap-OO:RR:..", "name": "Orbi RBRE960 (Router)", "mac": "..",
                 "is_base": True, "clients": [<mac>, ...]},
                {"id": "ap-SA:T1:..", "name": "Orbi satellite (XYZW)", "mac": "..",
                 "is_base": False, "clients": [<mac>, ...]},
            ],
            "devices": {<mac>: {<full inventory device dict>}},
            "unmapped": [<mac>, ...],   # devices we couldn't place under any infra node
            "stats": {"total": N, "wired_mapped": N, "wireless_mapped": N, "unmapped": N},
        }

    All inputs are injectable so unit tests don't have to hit the network --
    the production callers default to live inventory + live switch query.
    """
    if inventory is None:
        inventory = _load_homenet_inventory()
    devices_by_mac = dict(inventory.get("devices", {}))

    # ── Switch / wired-port mapping ────────────────────────────────────
    # _tplink_snmp_query returns mac_table = [{mac: "AA:BB:..", port_index: N}].
    # We invert to {port: [macs_seen_on_that_port]}. A trunk port may carry
    # many MACs (the Orbi router on its uplink port carries every wireless
    # client) -- the renderer treats those as "see AP for client list" rather
    # than draw 80 lines.
    switch_ports: dict[int, list[str]] = {}
    if switch_data is None:
        try:
            switch_data = _tplink_get_data()
        except Exception as e:  # noqa: BLE001 -- best-effort; topology still useful without.
            # Don't crash the route -- the UI surfaces the error string in
            # the per-switch ``error`` field of the response, which the
            # diagram renders as "switch unreachable" under the switch box.
            switch_data = {"error": str(e)}
    if isinstance(switch_data, dict) and not switch_data.get("error"):
        for entry in switch_data.get("mac_table") or []:
            mac = (entry.get("mac") or "").upper()
            port = entry.get("port_index")
            if not mac or port is None:
                continue
            switch_ports.setdefault(int(port), []).append(mac)

    # ── Orbi satellite mapping ─────────────────────────────────────────
    # Each wireless device's ``conn_ap_mac`` field tells us which Orbi node
    # (router or satellite) it's associated with. Bucket clients by AP MAC.
    aps_by_mac: dict[str, list[str]] = {}
    for mac, dev in devices_by_mac.items():
        ap_mac = (dev.get("conn_ap_mac") or "").upper()
        if not ap_mac:
            continue
        aps_by_mac.setdefault(ap_mac, []).append(mac.upper())

    # If the Orbi base router itself appears in the inventory we want its
    # entry too -- by IP since the MAC isn't pinned.
    orbi_base_mac = ""
    for mac, dev in devices_by_mac.items():
        if dev.get("ip") == "10.0.0.1":
            orbi_base_mac = mac.upper()
            break

    # Pull cached satellite names from the Orbi (if reachable). 5-min TTL
    # means at most one extra SOAP call per topology refresh in practice.
    sat_names_from_orbi = _get_orbi_satellite_names_cached()

    aps_out = []
    for ap_mac, clients in sorted(aps_by_mac.items()):
        ap_is_base = ap_mac == orbi_base_mac
        aps_out.append(
            {
                "id": f"ap-{ap_mac}",
                "mac": ap_mac,
                "name": _label_orbi_node(ap_mac, devices_by_mac, ap_is_base, sat_names_from_orbi),
                "is_base": ap_is_base,
                "clients": sorted(clients),
            }
        )
    # Ensure the Orbi base appears even if it has no associated clients
    # (rare -- but happens on a fresh deploy with no wireless devices yet).
    if orbi_base_mac and not any(a["mac"] == orbi_base_mac for a in aps_out):
        aps_out.insert(
            0,
            {
                "id": f"ap-{orbi_base_mac}",
                "mac": orbi_base_mac,
                "name": _label_orbi_node(orbi_base_mac, devices_by_mac, True, sat_names_from_orbi),
                "is_base": True,
                "clients": [],
            },
        )

    # ── Satellite-name plumbing (#9) ──────────────────────────────────
    # Synthesise a placeholder inventory entry for every satellite MAC that
    # isn't already in the inventory. The Orbi SOAP endpoint returns clients
    # only -- it never returns the satellites themselves -- so without this
    # step the user has nothing to point the device-edit modal at when they
    # want to name "Living Room Orbi" / "Kitchen Orbi" / etc. Once the entry
    # exists the existing /api/homenet/device/update flow handles the rest.
    inventory_dirty = False
    for ap in aps_out:
        ap_mac = ap["mac"]
        # Synthesise an entry for any AP that's not in inventory -- this
        # includes BOTH satellites AND the base when the inventory hasn't
        # captured the base via ARP yet. Without the base entry, the user
        # can't rename "Orbi RBRE960 (Base)" to e.g. "Living Room Orbi" via
        # the existing edit modal.
        if ap_mac and ap_mac not in devices_by_mac:
            devices_by_mac[ap_mac] = {
                "mac": ap_mac,
                "ip": "",
                "hostname": "",
                "vendor": "Netgear",
                "network": "wireless",
                "source": "topology_synthesised",
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "friendly_name": "",
                "category": "Network",
                "location": "",
                "notes": "Orbi satellite — auto-added by topology builder. Open this row to set a friendly name (e.g. 'Living Room Orbi').",
                "active": True,
            }
            inventory_dirty = True
    if inventory_dirty and inventory is not None and isinstance(inventory.get("devices"), dict):
        # Mirror the synthesised entries into the live inventory dict so the
        # next /api/homenet/inventory call surfaces them in the device table
        # too. Best-effort: if persistence fails (write lock contention etc.)
        # the topology still renders, just without the satellite entries
        # showing up in the table until the next scan.
        for ap_mac, entry in devices_by_mac.items():
            if entry.get("source") == "topology_synthesised":
                inventory["devices"].setdefault(ap_mac, entry)
        try:
            _save_homenet_inventory(inventory)
        except Exception:  # noqa: BLE001 -- save failure is non-fatal
            pass

    # ── Switch wrapper ────────────────────────────────────────────────
    switch_mac = "DC:62:79:F3:52:5C"
    switches_out = [
        {
            "id": f"switch-{switch_mac}",
            "mac": switch_mac,
            "name": _INFRA_LABELS[switch_mac]["name"],
            "ports": {p: sorted(macs) for p, macs in sorted(switch_ports.items())},
            "available": bool(switch_ports),
            "error": (switch_data or {}).get("error", ""),
        }
    ]

    # ── Identify the router (do this BEFORE classification) ───────────
    router = {"id": "router", "name": "Verizon CR1000A", "ip": "192.168.1.1", "mac": ""}
    for mac, dev in devices_by_mac.items():
        if dev.get("ip") == "192.168.1.1":
            router["mac"] = mac.upper()
            break

    # ── Build the runtime infrastructure-MAC set ──────────────────────
    # Anything in here is excluded from device-tier classification (it's
    # rendered as a tier-2 infra node instead). Three sources contribute:
    #   1. Hard-pinned MACs from _INFRA_LABELS (the TP-Link switch)
    #   2. The router's MAC (resolved from inventory by IP lookup above)
    #   3. Every AP MAC we discovered (Orbi base + satellites)
    #   4. Devices whose hostname matches a known infra pattern -- catches
    #      the case where a router/AP is in the inventory under multiple
    #      MACs (Orbi WAN-side at 192.x AND LAN-side at 10.0.0.1)
    infra_macs: set[str] = set(_INFRA_LABELS.keys())
    if router["mac"]:
        infra_macs.add(router["mac"])
    for ap in aps_out:
        infra_macs.add(ap["mac"])
    for mac, dev in devices_by_mac.items():
        if _is_infra_by_hostname(dev):
            infra_macs.add(mac.upper())

    # ── Compute mapped / unmapped sets ────────────────────────────────
    mapped_wired: set[str] = set()
    for port_macs in switch_ports.values():
        for m in port_macs:
            if m in devices_by_mac and m not in infra_macs:
                mapped_wired.add(m)
    mapped_wireless: set[str] = set()
    for ap in aps_out:
        for m in ap["clients"]:
            if m in devices_by_mac:
                mapped_wireless.add(m)

    all_macs = set(devices_by_mac.keys())
    # Don't count infrastructure as "unmapped" -- we render it explicitly.
    candidate = all_macs - infra_macs
    leftover = candidate - mapped_wired - mapped_wireless

    # ── MoCA bridges ──────────────────────────────────────────────────
    # Devices we recognise as MoCA endpoints (Actiontec ECB6200, FiOS Set-
    # Top Boxes, etc.) get their own bucket. They're "wired" but not on the
    # switch's MAC table because they sit on the coax → Verizon path. The
    # remaining wired devices that are leftover AND not MoCA bridges go
    # into "Verizon-direct or via MoCA" -- the catch-all explanation for
    # "wired but not seen by the switch".
    moca_bridges: list[str] = []
    leftover_after_moca: set[str] = set()
    for m in leftover:
        dev = devices_by_mac.get(m, {})
        if _is_moca_bridge(dev):
            moca_bridges.append(m)
        else:
            leftover_after_moca.add(m)
    moca_bridges.sort()

    # Build the bridge -> [downstream device MACs] mapping. The user marks
    # each downstream device's parent via behind_moca_bridge in the edit
    # modal; we just collect by bridge MAC. Devices pointing to a bridge
    # MAC that's no longer in moca_bridges (e.g. the user removed it from
    # inventory) are silently dropped from the tree but still show up in
    # via_moca/verizon_lan via the leftover bucketing below.
    moca_bridge_set = set(moca_bridges)
    moca_children: dict[str, list[str]] = {b: [] for b in moca_bridges}
    devices_behind_a_bridge: set[str] = set()
    for m, dev in devices_by_mac.items():
        parent = (dev.get("behind_moca_bridge") or "").upper().strip()
        if parent and parent in moca_bridge_set and m != parent:
            moca_children[parent].append(m)
            devices_behind_a_bridge.add(m)
    for k in moca_children:
        moca_children[k].sort()

    # Wired devices that aren't on the switch AND aren't a MoCA bridge.
    # The user explicitly asked for these to be split into two columns
    # (2026-04-25) -- "Verizon LAN" and "via MoCA" are physically distinct
    # paths (the MoCA traffic never traverses the Verizon's LAN ports;
    # it rides the coax from a downstream MoCA bridge into the Verizon's
    # built-in MoCA bridge). Without TP-Link SNMP OR Verizon API topology
    # data we can't auto-classify, so we honour the per-device user-set
    # ``wired_via`` field set via the device-edit modal:
    #   - "moca"        -> via_moca bucket
    #   - "verizon_lan" -> verizon_lan bucket
    #   - "switch"      -> stays out of these buckets (force into switch
    #                      column; useful when SNMP works but the MAC
    #                      table is stale and missed this device)
    #   - "" (unknown)  -> verizon_lan by default. Most home setups have
    #                      far more Verizon-LAN-attached devices than
    #                      MoCA-attached ones (MoCA is usually 1-2 STBs),
    #                      so this default minimises the user's tagging
    #                      burden -- they only have to mark the MoCA
    #                      devices, not all the Verizon ones.
    # Devices the user has nested under a specific MoCA bridge live in the
    # MoCA Bridges column tree; exclude them from the flat via_moca /
    # verizon_lan buckets to avoid double-rendering.
    wired_leftover = [
        m
        for m in leftover_after_moca
        if devices_by_mac.get(m, {}).get("network") == "wired" and m not in devices_behind_a_bridge
    ]
    via_moca: list[str] = []
    verizon_lan: list[str] = []
    switch_forced: set[str] = set()
    for m in wired_leftover:
        wired_via = (devices_by_mac.get(m, {}).get("wired_via") or "").lower()
        if wired_via == "moca":
            via_moca.append(m)
        elif wired_via == "switch":
            # User force-mapped to switch -- treat as if SNMP had reported
            # them. Add to a synthetic port-0 bucket on the switch so they
            # render in the switch column AND get excluded from the wireless
            # -leftover -> unmapped path computed below.
            switch_forced.add(m)
            switches_out[0]["ports"].setdefault(0, []).append(m)
            mapped_wired.add(m)
        else:
            verizon_lan.append(m)
    via_moca.sort()
    verizon_lan.sort()
    if switch_forced:
        switches_out[0]["available"] = True
    # Backwards-compatible alias retained so callers/tests that still
    # reference the combined list don't break. New code should use the
    # split buckets above.
    via_verizon_or_moca: list[str] = sorted(via_moca + verizon_lan)

    # Wireless leftovers split by source. Bug 2026-04-25: dumping every
    # wireless device with empty ``conn_ap_mac`` into "Unmapped" was
    # misleading -- those devices ARE on the Orbi mesh, we just don't know
    # which node, because Orbi's GetAttachDevice2 SOAP response only fills
    # ConnAPMAC for some clients (firmware-dependent + roaming-state-
    # dependent). Now we route Orbi-discovered wireless leftovers to
    # ``orbi_mesh_unknown_ap`` so the user understands "I see them, just
    # not their AP". ARP-only wireless ghosts (no Orbi entry) stay in
    # ``unmapped`` -- those are usually offline / stale.
    wireless_leftover = leftover_after_moca - set(via_verizon_or_moca) - switch_forced
    orbi_mesh_unknown_ap: list[str] = sorted(
        m for m in wireless_leftover if devices_by_mac.get(m, {}).get("source") == "orbi"
    )
    unmapped = sorted(wireless_leftover - set(orbi_mesh_unknown_ap))

    return {
        "ok": True,
        "router": router,
        "switches": switches_out,
        "aps": aps_out,
        # MoCA-over-coax bridges detected by vendor name (Actiontec etc.).
        # Rendered as their own infrastructure tier in the diagram so the
        # user can see which devices are "going through MoCA" at a glance.
        "moca_bridges": moca_bridges,
        # Per-bridge children mapping: {bridge_mac: [child_mac, ...]}.
        # Populated from each device's behind_moca_bridge field. The UI
        # renders this as a tree under each bridge in the MoCA Bridges
        # column. Bridges with no children render as a leaf entry.
        "moca_children": moca_children,
        # Wired devices that aren't on the switch MAC table AND aren't a
        # MoCA bridge themselves. Common causes: (a) plugged direct into
        # the Verizon LAN ports, (b) downstream of a MoCA bridge, (c) the
        # TP-Link SNMP credential isn't configured so no MAC table at all.
        # Kept for backwards compatibility; UI prefers the split buckets.
        "via_verizon_or_moca": via_verizon_or_moca,
        # Split buckets (per-device user-set ``wired_via`` field):
        "verizon_lan": verizon_lan,  # plugged into the Verizon's LAN ports
        "via_moca": via_moca,  # downstream of a MoCA bridge (coax)
        # Wireless devices the Orbi reports but doesn't tell us which AP
        # they're attached to. Known firmware behaviour -- the SOAP
        # GetAttachDevice2 response leaves ConnAPMAC empty for some
        # clients. They're on the mesh somewhere; we just can't say where.
        "orbi_mesh_unknown_ap": orbi_mesh_unknown_ap,
        "devices": devices_by_mac,
        # Truly unmapped: not wired, not on switch, not in any AP's client
        # list, AND the Orbi never reported them either -- probably
        # offline ARP ghosts from a previous scan.
        "unmapped": unmapped,
        "stats": {
            "total": len(devices_by_mac),
            "wired_mapped": len(mapped_wired),
            "wireless_mapped": len(mapped_wireless),
            "moca_bridges": len(moca_bridges),
            "via_verizon_or_moca": len(via_verizon_or_moca),
            "verizon_lan": len(verizon_lan),
            "via_moca": len(via_moca),
            "orbi_mesh_unknown_ap": len(orbi_mesh_unknown_ap),
            "unmapped": len(unmapped),
            "switch_available": switches_out[0]["available"] if switches_out else False,
        },
    }


@homenet_bp.route("/api/homenet/topology")
def homenet_topology():
    """Hierarchical network topology for the Network Topology Diagram (#9).

    Joins the cached device inventory with the live TP-Link MAC table and
    the Orbi per-AP client mapping. Read-only -- doesn't trigger a fresh
    scan; the user clicks "Refresh" in the homenet tab if they want
    fresher inventory data.
    """
    return jsonify(build_topology())
