# WinDesktopMgr

A local Windows system management dashboard built with Python and Flask. 
Runs at `http://localhost:5000` and launches automatically at login.

Built specifically for the **Dell XPS 8960 (i9-14900K)** but works on any Windows 11 machine.

![Python](https://img.shields.io/badge/Python-3.14-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Windows](https://img.shields.io/badge/Windows-11-lightblue)

---

## Features

| Tab | What it does |
|-----|-------------|
| ⟳ **Driver Manager** | Scans installed drivers, checks Windows Update for pending updates |
| ⚠ **BSOD Dashboard** | Crash history, stop code analysis, faulty driver identification |
| 🚀 **Startup Manager** | Every startup entry with plain-English descriptions, enable/disable toggles |
| 💾 **Disk Health** | Drive usage, physical disk health status |
| 🌐 **Network Monitor** | Active connections by process, adapter stats, suspicious port detection |
| 🔄 **Update History** | Full Windows Update history with failed update flagging |
| 📋 **Event Log** | Searchable System/Application/Security log with smart noise filtering |
| ⚡ **Processes** | Running processes with plain-English descriptions and kill button |
| 🌡 **Temps & Power** | CPU/GPU temperatures, utilisation gauges, auto-refresh |
| ⚙ **Services** | Windows services with descriptions, start/stop/disable controls |
| 📈 **Health History** | SystemHealthDiag report scores charted over time |
| ⏱ **System Timeline** | BSODs, updates, driver changes correlated on one timeline |
| 🧠 **Memory Analysis** | RAM by category, AV comparison |
| 🔩 **BIOS & Firmware** | Current BIOS version and Dell update check |

---

## Self-Learning Knowledge Base

Unknown Event IDs, BSOD stop codes, startup items, services, and processes are 
automatically researched and cached locally:

- **Windows Provider Registry** — reads Windows' own event metadata (offline)
- **File version info** — reads embedded publisher/description from exe files
- **Microsoft Learn API** — web fallback for anything not found locally
- Results cached permanently — each item looked up at most once, retried if stale

---

## Requirements

- Windows 11
- Python 3.11+
- Flask

```powershell
pip install flask
```

---

## Quick Start

```powershell
git clone https://github.com/shigs1978/windesktopmgr.git
cd windesktopmgr
pip install flask
py.exe .\windesktopmgr.py
```

Open `http://localhost:5000`

---

## Run at Login (optional)

```powershell
# Run once as Administrator
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\setup-startup.ps1
```

Registers a Windows Scheduled Task that starts Flask at login and opens the browser automatically.

---

## Project Structure

```
windesktopmgr/
├── windesktopmgr.py       # Flask backend — all data collection and APIs
├── setup-startup.ps1      # Login startup task registration (run once as Admin)
├── requirements.txt       # Python dependencies
├── .gitignore
├── README.md
└── templates/
    └── index.html         # Single-page frontend (dark theme)
```

---

## Background

Built to diagnose recurring `HYPERVISOR_ERROR` BSODs on a Dell XPS 8960 (i9-14900K), 
caused by `intelppm.sys` interacting badly with Hyper-V during CPU C-State transitions. 
Grew into a full Windows management dashboard from there.

---

## License

MIT
