# WindowsDriverMgr — Dell XPS 8960

A Python + Flask web app that scans your installed Windows drivers,
compares them against Dell's support catalog, and highlights anything
that needs updating — all in a slick browser dashboard.

---

## Setup

```
pip install -r requirements.txt
python windowsdrivermgr.py
```

Then open **http://localhost:5000** in your browser and click **Run Scan**.

---

## How it works

1. **Scan** — PowerShell enumerates all signed drivers via `Win32_PnPSignedDriver`
2. **Fetch** — Dell's driver API is queried for the XPS 8960 catalog
3. **Compare** — Installed versions are fuzzy-matched and compared
4. **Display** — Results shown with status badges, version diff, and direct download links

## Driver status

| Badge | Meaning |
|-------|---------|
| 🟠 Update Available | A newer version exists on Dell's site |
| 🟢 Up to Date | Installed version matches or exceeds Dell's latest |
| ⚫ Unknown | No matching Dell driver found (may be 3rd-party) |

## Files

```
driver_checker/
  windowsdrivermgr.py    ← Flask backend
  templates/
    index.html        ← Browser UI
  requirements.txt
  README.md
```

## Notes

- Requires Windows (uses PowerShell + WMI)
- Run as a standard user — no admin needed for reading driver info
- Dell API is public, no auth required
- Scans typically take 15–30 seconds
