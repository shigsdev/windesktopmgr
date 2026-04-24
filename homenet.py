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

    _save_homenet_inventory(inventory)
    return jsonify({"ok": True, "message": "Device updated"})


@homenet_bp.route("/api/homenet/switch")
def homenet_switch_data():
    """Get TP-Link switch port status, traffic stats, and MAC table."""
    result = _tplink_get_data()
    return jsonify(result)
