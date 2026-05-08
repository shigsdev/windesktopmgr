"""scripts/probe_verizon_moca.py -- one-off exploration to find the
CR1000A's MoCA-topology page (backlog #42).

Approach: authenticate using the existing _arc_md5 / _verizon_encode_password
helpers (which we already use for the device-list scrape), then probe a
list of likely URL paths and report which return interesting HTML / JSON.

This is a SPIKE -- output guides the production parser. Not committed to
the regular scan loop; not run from CI.

Usage: python scripts/probe_verizon_moca.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a script from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
import urllib3

from homenet import _arc_md5, _get_homenet_cred, _verizon_encode_password

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Candidate URL paths -- guesses based on CR1000A naming patterns we've
# seen in cgi_basic.js + the Vue.js SPA's hash routes.
CANDIDATES = [
    # The known-working endpoint (we use it for device list) -- includes
    # to see if MoCA bridges hide in dump_toplogy_* rod values
    "/cgi/cgi_basic.js",
    "/cgi/cgi_status.js",
    # More cgi_*.js endpoints with broader name guesses
    "/cgi/cgi_internet.js",
    "/cgi/cgi_local.js",
    "/cgi/cgi_home.js",
    "/cgi/cgi_settings.js",
    "/cgi/cgi_diag.js",
    "/cgi/cgi_diagnostics.js",
    "/cgi/cgi_log.js",
    "/cgi/cgi_misc.js",
    "/cgi/cgi_full.js",
    "/cgi/cgi_get.js",
    "/cgi/cgi_data.js",
    "/cgi/cgi_state.js",
    # Plain "moca" anchored under /cgi without the cgi_ prefix
    "/cgi/moca.js",
    "/cgi/topology.js",
    "/cgi/diag.js",
    # The SPA-served pages -- maybe under /index.htm or a sub-route
    "/index.htm",
    # Try the JS bundle directly -- search for MoCA references
    "/static/js/app.js",
    "/static/js/chunk-vendors.js",
    "/js/app.js",
]


def main() -> int:
    user, pw = _get_homenet_cred("verizon")
    if not user or not pw:
        print("ERROR: no Verizon credentials. Add them via the Network Settings tab first.")
        return 2

    base = "https://192.168.1.1"
    s = requests.Session()
    s.verify = False
    s.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": f"{base}/",
            "Origin": base,
        }
    )

    print("Authenticating…")
    r = s.get(f"{base}/loginStatus.cgi", timeout=10)
    token = (r.json() or {}).get("loginToken", "")
    if not token:
        print(f"ERROR: no loginToken in /loginStatus.cgi response: {r.text[:200]}")
        return 2

    payload = {
        "luci_username": _arc_md5(user),
        "luci_password": _verizon_encode_password(pw, token),
        "luci_view": "Desktop",
        "luci_token": token,
        "luci_keep_login": "0",
    }
    r = s.post(f"{base}/login.cgi", data=payload, timeout=10, allow_redirects=False)
    if "sysauth" not in s.cookies.get_dict():
        print(f"ERROR: login failed (HTTP {r.status_code}) -- check creds")
        return 2
    print("  authenticated.")

    print()
    print(f"Probing {len(CANDIDATES)} candidate URLs…")
    print("-" * 70)
    for path in CANDIDATES:
        url = f"{base}{path}"
        try:
            r = s.get(url, timeout=8, allow_redirects=False)
            ct = r.headers.get("Content-Type", "").split(";")[0]
            body = r.text or ""
            # Look for moca-y signal in the body
            moca_hits = body.lower().count("moca")
            status_marker = ""
            if r.status_code == 200 and len(body) > 0:
                status_marker = " <- candidate"
                if moca_hits > 0:
                    status_marker = f" <- HAS {moca_hits} 'moca' hits"
            print(f"  {r.status_code} {ct:20s} {len(body):6d}b  {path}{status_marker}")
        except Exception as e:
            print(f"  ERR  {path}: {type(e).__name__}: {str(e)[:60]}")

    print()
    print("Following the /index.htm redirect…")
    r = s.get(f"{base}/index.htm", timeout=8, allow_redirects=False)
    print(f"  /index.htm -> {r.status_code} {r.headers.get('Location', '')}")

    # Dump cgi_basic.js IN FULL so we can see if dump_toplogy_*
    # contains MoCA bridges already and we just weren't extracting them.
    print()
    print("=== /cgi/cgi_basic.js FULL DUMP ===")
    r = s.get(f"{base}/cgi/cgi_basic.js", timeout=10)
    print(r.text)
    print(f"  ({len(r.text)} bytes)")
    print()
    print("=== /cgi/cgi_status.js FULL DUMP ===")
    r = s.get(f"{base}/cgi/cgi_status.js", timeout=10)
    print(r.text)
    print(f"  ({len(r.text)} bytes)")

    # Try POST as well -- some routers gate data behind POST
    print()
    print("Trying POST on candidate endpoints with empty body…")
    for path in ["/cgi/cgi_moca.js", "/cgi/cgi_topology.js", "/cgi/cgi_full.js"]:
        try:
            r = s.post(f"{base}{path}", data={}, timeout=8)
            print(f"  POST {path} -> {r.status_code} {len(r.text)}b")
            if r.status_code == 200 and "moca" in r.text.lower():
                print(f"    HAS MoCA -- first 400 chars: {r.text[:400]}")
        except Exception as e:
            print(f"  POST {path} -> ERR {type(e).__name__}")

    # Spelunk the SPA shell -- it should reference its own JS bundles
    print()
    print("=== /  (SPA shell) ===")
    r = s.get(f"{base}/", timeout=8)
    print(r.text)
    print(f"  ({len(r.text)} bytes)")

    # Extract <script src=...> entries
    import re

    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, flags=re.IGNORECASE)
    print(f"  scripts referenced: {script_srcs}")

    # Pull each referenced script and grep for MoCA / cgi paths
    for src in script_srcs:
        url = src if src.startswith("http") else f"{base}{src if src.startswith('/') else '/' + src}"
        try:
            r2 = s.get(url, timeout=15)
            print()
            print(f"=== {url} ({len(r2.text)} bytes) ===")
            # Look for MoCA references
            moca_refs = re.findall(r'["\'][^"\']{0,40}[Mm][Oo][Cc][Aa][^"\']{0,40}["\']', r2.text)
            print(f"  MoCA-mentioning string literals: {len(moca_refs)}")
            for ref in moca_refs[:30]:
                print(f"    {ref}")
            # Look for cgi path references
            cgi_refs = re.findall(r'["\']/?cgi/[a-zA-Z0-9_]+\.[a-z]+["\']', r2.text)
            cgi_uniq = sorted(set(cgi_refs))
            print(f"  /cgi/* path literals: {len(cgi_uniq)}")
            for ref in cgi_uniq:
                print(f"    {ref}")
        except Exception as e:
            print(f"  {url} -> ERR {type(e).__name__}: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
