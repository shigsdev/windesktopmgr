"""BIOS & firmware checker for WinDesktopMgr (#54 PR J).

get_current_bios() reads Win32_BIOS / Win32_BaseBoard via the shared
_wmi_conn helper. check_dell_bios_update() checks for Dell XPS 8960 BIOS
updates (Dell Command Update CLI, then the public Dell catalog) and caches
the result in BIOS_CACHE_FILE. get_bios_status() combines the two and
summarize_bios() folds the result into the dashboard insight/action shape.

_wmi_conn is lazy-imported from windesktopmgr inside get_current_bios, and
get_bios_status resolves get_current_bios / check_dell_bios_update via the
windesktopmgr namespace -- both break the import cycle AND keep the
mocker.patch("windesktopmgr.X") test hooks effective after the move. The
Flask routes (/api/bios/status, /api/bios/cache/clear via BIOS_CACHE_FILE),
/api/selftest globals() lookup, get_summary dispatch, NLQ dispatch, and the
dashboard fan-out call the re-exported bindings.

BIOS_CACHE_FILE is owned by this module: check_dell_bios_update reads/writes
it through the module-local name, so tests that exercise the cache branch
patch bios.BIOS_CACHE_FILE (the clear-cache route reads the windesktopmgr
re-export, so route tests patch windesktopmgr.BIOS_CACHE_FILE).

_insight / _parse_ts are duplicated locally (disk.py / bsod.py precedent).
"""

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BIOS_CACHE_FILE = os.path.join(APP_DIR, "bios_cache.json")


def _parse_ts(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _insight(level: str, text: str, action: str = "") -> dict:
    return {"level": level, "text": text, "action": action}


def _get_service_tag() -> str:
    """Dell service tag from WMI Win32_BIOS, bounded so a wedged Winmgmt can't
    hang the BIOS-update check or leak a stuck COM thread."""

    def _work():
        from windesktopmgr import _wmi_conn  # lazy: wdm-resident, breaks import cycle

        return _wmi_conn().Win32_BIOS()[0].SerialNumber or ""

    from windesktopmgr import bounded_wmi_query  # lazy: wdm-resident, breaks import cycle

    return bounded_wmi_query(_work, timeout_s=8.0, fallback="", label="Dell service tag")


def get_current_bios() -> dict:
    # _wmi_conn / bounded_wmi_query live in windesktopmgr; lazy-import to break
    # the cycle and keep mocker.patch("windesktopmgr._wmi_conn") effective.
    def _work():
        from windesktopmgr import _wmi_conn

        c = _wmi_conn()
        bios = c.Win32_BIOS()[0]
        board = c.Win32_BaseBoard()[0]
        raw_date = bios.ReleaseDate or ""
        bios_date = ""
        if raw_date and len(raw_date) >= 8:
            try:
                bios_date = datetime.strptime(raw_date[:8], "%Y%m%d").strftime("%B %d, %Y")
            except Exception:  # noqa: BLE001 — unparseable BIOS date, fall back to raw
                bios_date = raw_date[:8]
        return {
            "BIOSVersion": bios.SMBIOSBIOSVersion,
            "ReleaseDate": raw_date,
            "Manufacturer": bios.Manufacturer,
            "BoardProduct": board.Product,
            "BoardMfr": board.Manufacturer,
            "BIOSDateFormatted": bios_date,
        }

    from windesktopmgr import bounded_wmi_query  # lazy: wdm-resident, breaks import cycle

    return bounded_wmi_query(_work, timeout_s=8.0, fallback={}, label="current BIOS")


def check_dell_bios_update(board_product: str, current_version: str) -> dict:
    """
    Check for Dell XPS 8960 BIOS updates via PowerShell on the local machine.
    Priority:
      1. Dell Command Update CLI (dcucli.exe) — already installed on XPS systems
      2. Dell public update catalog XML (downloads.dell.com/catalog/CatalogPC.cab)
         parsed via PowerShell Expand-Archive — no API, just a static file download
      3. Windows Update pending driver check — catches BIOS updates via WU
    Results cached for 24 hours.
    """
    # get_windows_update_drivers (WU fallback) lives in windesktopmgr;
    # lazy-import to break the cycle and keep mocker.patch effective. The
    # service-tag WMI lookup is bounded via _get_service_tag() above.
    from windesktopmgr import get_windows_update_drivers

    # ── Check cache ────────────────────────────────────────────────────────────
    try:
        if os.path.exists(BIOS_CACHE_FILE):
            with open(BIOS_CACHE_FILE, encoding="utf-8") as f:
                cached = json.load(f)
            age = (datetime.now(timezone.utc) - _parse_ts(cached.get("checked_at", ""))).total_seconds() / 3600
            if age < 24:
                return cached
    except Exception:
        pass

    # Get service tag dynamically from WMI (bounded)
    service_tag = ""
    tag = _get_service_tag()
    if tag and len(tag) >= 5:
        service_tag = tag

    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "current_version": current_version,
        "latest_version": None,
        "latest_date": None,
        "update_available": False,
        "release_notes": "",
        "service_tag": service_tag,
        "download_url": (
            f"https://www.dell.com/support/home/en-us/product-support/servicetag/{service_tag}/drivers"
            if service_tag
            else "https://www.dell.com/support/home/en-us"
        ),
        "source": "unknown",
        "error": None,
    }

    def _ver_gt(latest: str, current: str) -> bool:
        def _v(s):
            return [int(x) for x in re.split(r"[.\-]", str(s)) if x.isdigit()]

        try:
            return _v(latest) > _v(current)
        except Exception:
            return latest.strip() != current.strip()

    # ── Method 1: Dell Command Update CLI ─────────────────────────────────────
    # DCU is pre-installed on Dell XPS systems at a predictable path
    dcu_paths = [
        r"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
        r"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
        r"C:\Program Files\Dell\Dell Command Update\dcu-cli.exe",
    ]
    dcu_exe = next((p for p in dcu_paths if os.path.exists(p)), None)
    if dcu_exe:
        try:
            import tempfile
            import uuid

            tmp = os.path.join(tempfile.gettempdir(), f"dcu_scan_{uuid.uuid4().hex}.xml")
            subprocess.run(
                [dcu_exe, "/scan", f"-outputLog={tmp}", "-silent"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if os.path.exists(tmp):
                try:
                    with open(tmp, encoding="utf-8", errors="replace") as f:
                        xml_content = f.read()
                    # Find BIOS updates in the output
                    m = re.search(r'type="BIOS"[^/]*/.*?version="([0-9.]+)"', xml_content, re.DOTALL | re.IGNORECASE)
                    if not m:
                        m = re.search(r'BIOS.*?version="([0-9.]+)"', xml_content, re.DOTALL | re.IGNORECASE)
                    if m:
                        ver = m.group(1)
                        result["latest_version"] = ver
                        result["source"] = "dell_command_update"
                        result["update_available"] = _ver_gt(ver, current_version)
                        print(f"[BIOS] DCU found version: {ver}")
                finally:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        except Exception as e:
            result["error"] = f"DCU: {e}"
    else:
        print("[BIOS] DCU not found")

    # ── Method 2: Dell public catalog XML ──────────────────────────────────────
    # Pure-Python: urllib downloads the catalog, expand.exe (a Windows OS tool
    # — not PowerShell) extracts the .cab, ElementTree parses the XML. The
    # PowerShell heredoc this replaces was the last `subprocess powershell`
    # call in check_dell_bios_update (backlog #28 close-out).
    if not result["latest_version"]:
        import tempfile
        import urllib.request
        import xml.etree.ElementTree as ET

        cab_path = os.path.join(tempfile.gettempdir(), "DellCatalog.cab")
        xml_dir = os.path.join(tempfile.gettempdir(), "DellCatalog")
        xml_path = os.path.join(xml_dir, "CatalogPC.xml")
        try:
            # Fetch the catalog (~2 MB). Cap the read at 16 MB so a hostile
            # endpoint can't OOM us.
            req = urllib.request.Request(
                "https://downloads.dell.com/catalog/CatalogPC.cab",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                cab_bytes = resp.read(16_777_216)
            if not cab_bytes:
                raise RuntimeError("empty catalog download")
            with open(cab_path, "wb") as f:
                f.write(cab_bytes)
            os.makedirs(xml_dir, exist_ok=True)
            # No CAB extractor in the Python stdlib — use the OS's expand.exe
            # (not PowerShell). One light subprocess call, no PS process spawn.
            subprocess.run(
                ["expand.exe", cab_path, xml_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # XML element matching is case-INSENSITIVE here because the old
            # PowerShell relied on PS's case-insensitive property access
            # (`$_.componentType.value` vs the actual `ComponentType` element);
            # ElementTree is case-sensitive by default. The `{*}` namespace
            # wildcard handles the catalog's default xmlns.
            def _findall_ci(parent, name):
                t = name.lower()
                return [c for c in parent.iter() if c.tag.rsplit("}", 1)[-1].lower() == t]

            def _find_child_ci(parent, name):
                t = name.lower()
                for c in parent:
                    if c.tag.rsplit("}", 1)[-1].lower() == t:
                        return c
                return None

            # ruff S314: the XML source is the trusted Dell catalog over HTTPS
            # (fixed URL, 16 MB read cap above), and the catalog schema has no
            # external entities — adding a `defusedxml` dep for one parse is
            # disproportionate.
            tree = ET.parse(xml_path)  # noqa: S314
            root = tree.getroot()
            best = None
            best_date = ""
            for sc in _findall_ci(root, "SoftwareComponent"):
                ct = _find_child_ci(sc, "ComponentType")
                if ct is None or (ct.get("value") or "").upper() != "BIOS":
                    continue
                # Match on Model name *8960* OR systemID *0BC0* (XPS 8960).
                matched = False
                for m in _findall_ci(sc, "Model"):
                    mname = (m.get("name") or "").lower()
                    sysid = (m.get("systemID") or "").lower()
                    if "8960" in mname or "0bc0" in sysid:
                        matched = True
                        break
                if not matched:
                    continue
                rdate = sc.get("releaseDate", "")
                if best is None or rdate > best_date:
                    best = sc
                    best_date = rdate

            if best is not None:
                ver2 = best.get("dellVersion") or best.get("vendorVersion") or ""
                if ver2:
                    # Name/Display CDATA → element.text on the Display child.
                    name_text = ""
                    name_el = _find_child_ci(best, "Name")
                    if name_el is not None:
                        disp = _find_child_ci(name_el, "Display")
                        if disp is not None and disp.text:
                            name_text = disp.text.strip()
                    rel_path = best.get("path", "")
                    result["latest_version"] = ver2
                    result["latest_date"] = best_date
                    result["release_notes"] = name_text[:200]
                    if rel_path:
                        result["download_url"] = f"https://downloads.dell.com/{rel_path}"
                    result["source"] = "dell_catalog"
                    result["update_available"] = _ver_gt(ver2, current_version)
                    result["error"] = None
                    print(f"[BIOS] Catalog found version: {ver2}")
        except Exception as e2:  # noqa: BLE001
            if result["error"]:
                result["error"] += f" | Catalog: {e2}"
            else:
                result["error"] = f"Catalog: {e2}"
        finally:
            # Best-effort cleanup.
            try:
                if os.path.exists(cab_path):
                    os.remove(cab_path)
                if os.path.exists(xml_dir):
                    shutil.rmtree(xml_dir, ignore_errors=True)
            except Exception:  # noqa: BLE001
                pass

    # ── Method 3: Windows Update pending BIOS check ────────────────────────────
    # Reuses get_windows_update_drivers() — the WU "available drivers" search
    # already surfaces BIOS/Firmware updates, so there is no need for a second
    # COM search here. This also shares the _wu_driver_cache if a driver scan
    # has already run.
    if not result["latest_version"]:
        try:
            wu = get_windows_update_drivers()
            bios_u = None
            if wu:
                bios_u = next(
                    (u for u in wu.values() if re.search(r"BIOS|Firmware", u.get("Title", ""), re.IGNORECASE)),
                    None,
                )
            if bios_u:
                title = bios_u.get("Title", "")
                m = re.search(r"(\d+\.\d+[.\d]*)", title)
                ver3 = m.group(1) if m else ""
                if ver3:
                    result["latest_version"] = ver3
                    result["release_notes"] = title[:200]
                    result["source"] = "windows_update"
                    result["update_available"] = True  # WU only shows pending updates
                    result["error"] = None
                    print(f"[BIOS] Windows Update found BIOS update: {title}")
        except Exception:  # noqa: BLE001
            pass

    # ── Method 4: Get service tag for a direct personalised Dell support URL ────
    # If we didn't get it at the top (e.g. timeout), try once more
    if not result.get("service_tag"):
        try:
            tag = _get_service_tag()
            if tag and len(tag) >= 5:
                result["service_tag"] = tag
                result["download_url"] = (
                    f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers"
                )
                print(f"[BIOS] Service tag: {tag}")
        except Exception:
            pass

    # ── Save cache ────────────────────────────────────────────────────────────
    try:
        with open(BIOS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    print(f"[BIOS] Done: current={current_version} latest={result['latest_version']} source={result['source']}")
    return result


def get_bios_status() -> dict:
    # Resolve the two siblings via the windesktopmgr namespace (re-exported
    # there) so mocker.patch("windesktopmgr.get_current_bios" /
    # "windesktopmgr.check_dell_bios_update") stays effective after the #54 PR J
    # move -- same lazy-import indirection used for _wmi_conn above.
    from windesktopmgr import check_dell_bios_update, get_current_bios

    current = get_current_bios()
    version = current.get("BIOSVersion", "")
    update = check_dell_bios_update(current.get("BoardProduct", ""), version)
    return {"current": current, "update": update}


def summarize_bios(data: dict) -> dict:
    current = data.get("current", {})
    update = data.get("update", {})
    insights, actions = [], []
    version = current.get("BIOSVersion", "Unknown")
    bios_date = current.get("BIOSDateFormatted", "")
    insights.append(_insight("info", f"Current BIOS: {version} ({bios_date}, {current.get('Manufacturer', '')})."))
    tag = update.get("service_tag", "")
    tag_url = (
        f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers"
        if tag
        else "https://www.dell.com/support/home/en-us?app=drivers"
    )

    if update.get("update_available"):
        latest = update.get("latest_version", "")
        insights.append(
            _insight(
                "critical",
                f"BIOS update available: {latest} (you have {version}). "
                f"Update immediately — this may fix your HYPERVISOR_ERROR crashes.",
                "Update via Dell Command Update or download directly from Dell Support.",
            )
        )
        actions.append("Update BIOS via Dell Command Update")
    elif update.get("latest_version"):
        src = update.get("source", "")
        src_note = " (confirmed by Dell)" if src == "confirmed_current" else f" (source: {src})"
        insights.append(
            _insight(
                "ok",
                f"BIOS {version} is current — no update needed{src_note}. "
                f"Latest: {update['latest_version']} ({update.get('latest_date', '')}).",
            )
        )
        if update.get("release_notes"):
            insights.append(_insight("info", update["release_notes"]))
    else:
        insights.append(
            _insight(
                "info",
                f"Could not auto-detect latest version from Dell. Your current BIOS is {version}.",
                f"Check your personalised Dell page at: {tag_url}",
            )
        )
    # Special note for i9-14900K HYPERVISOR_ERROR
    # Only show the Raptor Lake note — framed correctly given BIOS is current
    insights.append(
        _insight(
            "info",
            "Your i9-14900K is affected by Intel Raptor Lake instability (intelppm.sys / HYPERVISOR_ERROR). "
            "BIOS 2.22.0 includes Intel microcode patches for this issue — your BIOS is current, no update needed. "
            "If HYPERVISOR_ERROR crashes continue, the remaining mitigations are: "
            "disable C-States in BIOS, and disable Memory Integrity in Windows Security > Core Isolation.",
            "To access BIOS settings: restart and press F2 at the Dell splash screen. "
            "Or from PowerShell (Admin): shutdown /r /fw /t 0",
        )
    )
    status = "critical" if update.get("update_available") else "warning" if not update.get("latest_version") else "ok"
    headline = (
        f"BIOS update available: {update.get('latest_version', '')}"
        if update.get("update_available")
        else f"BIOS {version} — {'up to date' if update.get('latest_version') else 'check manually'}"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}
