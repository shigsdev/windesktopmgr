"""Credentials & network-health collector for WinDesktopMgr (#54 PR F).

Reads (all best-effort, never raises to the caller):
- Windows Credential Manager entries (cmdkey)
- OneDrive / Microsoft 365 MSAL token-cache freshness
- SMB/CIFS + NFS mapped-drive connectivity (per-user registry walk)
- Fast Startup state (known cause of credential loss on reboot)
- McAfee firewall interference with SMB port 445
- Recent credential-failure Security-log events (4625/4648/4776)

plus summarize_credentials_network() which folds the raw reading into the
dashboard insight/action shape.

PowerShell runs via the shared `subprocess` module whose `.run` is replaced
by windesktopmgr._headless_subprocess_run at import time, so headless
console-window suppression + the `mocker.patch("windesktopmgr.subprocess.run")`
test hook both apply here unchanged. The Flask route + selftest + NLQ
dispatch live in windesktopmgr.py and call the re-exported bindings.

_insight / _parse_ts are duplicated locally (disk.py / bsod.py precedent)
to avoid a circular import for two trivial helpers.
"""

import json
import subprocess
from datetime import datetime, timezone


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


def get_credentials_network_health() -> dict:
    """
    Checks:
    - Windows Credential Manager stored credentials (email/OAuth/NAS)
    - OneDrive / Microsoft 365 MSAL token cache status
    - SMB / CIFS share connectivity and mapping status
    - NFS mounts (if NFS client is installed)
    - Fast Startup state (known cause of credential loss on reboot)
    - McAfee firewall interference with SMB port 445
    - Recent credential failure events from Security log (4625/4648/4776)
    """

    # ── Credential Manager entries ─────────────────────────────────────────────
    ps_creds = r"""
try {
    $creds = cmdkey /list 2>$null
    $lines = $creds -split "`n" | Where-Object { $_ -match "Target:|User:|Type:" }
    $entries = @()
    $current = @{}
    foreach ($line in $lines) {
        if ($line -match "Target:\s*(.+)") {
            if ($current.Count -gt 0) { $entries += [PSCustomObject]$current }
            $current = @{ Target = $Matches[1].Trim(); User = ""; Type = "" }
        } elseif ($line -match "User:\s*(.+)")  { $current.User = $Matches[1].Trim() }
        elseif ($line -match "Type:\s*(.+)")    { $current.Type = $Matches[1].Trim() }
    }
    if ($current.Count -gt 0) { $entries += [PSCustomObject]$current }
    $entries | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    # ── SMB / CIFS / mapped drives ─────────────────────────────────────────────
    ps_smb = r"""
$result = @{}
# All mapped drives (SMB/CIFS/NFS)
# Read from registry - works regardless of which user/session runs the script
$mappedDrives = @()
try {
    # Get all logged-on user SIDs from the registry
    $userSIDs = @()
    $profileList = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue
    foreach ($profile in $profileList) {
        $sid = $profile.PSChildName
        if ($sid -match "^S-1-5-21-") { $userSIDs += $sid }
    }
    # Also try current user
    $currentSID = (New-Object Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($currentSID -notin $userSIDs) { $userSIDs += $currentSID }

    foreach ($sid in $userSIDs) {
        $netPath = "Registry::HKU\$sid\Network"
        if (Test-Path $netPath) {
            $driveMappings = Get-ChildItem $netPath -ErrorAction SilentlyContinue
            foreach ($d in $driveMappings) {
                try {
                    $uncPath = (Get-ItemProperty $d.PSPath -Name RemotePath -ErrorAction Stop).RemotePath
                    $letter  = $d.PSChildName
                    $proto   = if ($uncPath -match '^//') { "NFS" } else { "SMB/CIFS" }
                    $portNum = if ($proto -eq "NFS") { 2049 } else { 445 }
                    $dialect = ""
                    $reachable = $false
                    try {
                        if ($uncPath -match '^\\\\([^\\]+)') {
                            $nasHost = $Matches[1]
                            $tcp  = New-Object Net.Sockets.TcpClient
                            $conn = $tcp.BeginConnect($nasHost, $portNum, $null, $null)
                            $reachable = $conn.AsyncWaitHandle.WaitOne(1500, $false)
                            $tcp.Close()
                            if ($reachable -and $proto -eq "SMB/CIFS") {
                                try {
                                    $sc = Get-SmbConnection -ServerName $nasHost -ErrorAction SilentlyContinue |
                                          Select-Object -First 1
                                    if ($sc) { $dialect = $sc.Dialect }
                                } catch {}
                            }
                        }
                    } catch { $reachable = $false }
                    $mappedDrives += [PSCustomObject]@{
                        Name        = $letter
                        Root        = "$letter`:\"
                        DisplayRoot = $uncPath
                        Reachable   = [bool]$reachable
                        Protocol    = $proto
                        Port        = $portNum
                        Dialect     = $dialect
                    }
                } catch {}
            }
        }
    }
} catch {}

# Fallback: also check current session Get-PSDrive
try {
    $psDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot -ne $null -and $_.DisplayRoot -ne "" }
    foreach ($pd in $psDrives) {
        $disp = $pd.DisplayRoot
        if ($disp -match '^\\\\' -or $disp -match '^//') {
            $alreadyAdded = $mappedDrives | Where-Object { $_.Name -eq $pd.Name }
            if (-not $alreadyAdded) {
                # TCP port 445 check - works from non-interactive sessions
            $reachable = $false
            try {
                if ($pd.DisplayRoot -match '^\\\\([^\\]+)') {
                    $h = $Matches[1]
                    $t = New-Object Net.Sockets.TcpClient
                    $c = $t.BeginConnect($h, 445, $null, $null)
                    $reachable = $c.AsyncWaitHandle.WaitOne(1000, $false)
                    $t.Close()
                }
            } catch {}
                $proto     = if ($disp -match '^//') { "NFS" } else { "SMB/CIFS" }
                $portNum   = if ($proto -eq "NFS") { 2049 } else { 445 }
                $dialect   = ""
                $mappedDrives += [PSCustomObject]@{
                    Name        = $pd.Name
                    Root        = $pd.Root
                    DisplayRoot = $disp
                    Reachable   = [bool]$reachable
                    Protocol    = $proto
                    Port        = $portNum
                    Dialect     = $dialect
                }
            }
        }
    }
} catch {}

$result.MappedDrives = $mappedDrives

# SMB/CIFS sessions (active connections from this PC)
try {
    $sessions = Get-SmbConnection -ErrorAction Stop
    $result.SmbConnections = @($sessions | ForEach-Object {
        [PSCustomObject]@{
            ServerName  = $_.ServerName
            ShareName   = $_.ShareName
            UserName    = $_.UserName
            Dialect     = $_.Dialect
            Redirected  = $_.Redirected
        }
    })
} catch { $result.SmbConnections = @() }

# CIFS net use connections
try {
    $netuse = net use 2>$null | Where-Object { $_ -match "\\" }
    $result.NetUseLines = @($netuse)
} catch { $result.NetUseLines = @() }

# NFS mounts (Windows NFS client)
try {
    $nfs = Get-NfsMappedDrive -ErrorAction Stop
    $result.NfsMounts = @($nfs | ForEach-Object {
        [PSCustomObject]@{
            LocalPath  = $_.LocalPath
            RemotePath = $_.RemotePath
            Mounted    = $_.IsMounted
        }
    })
} catch { $result.NfsMounts = @() }

# SMB client configuration
try {
    $cfg = Get-SmbClientConfiguration -ErrorAction Stop
    $result.SmbConfig = [PSCustomObject]@{
        RequireSecuritySignature = $cfg.RequireSecuritySignature
        EnableSecuritySignature  = $cfg.EnableSecuritySignature
        DirectoryCacheLifetime   = $cfg.DirectoryCacheLifetime
    }
} catch { $result.SmbConfig = $null }

$result | ConvertTo-Json -Depth 3
"""

    # ── OneDrive / Microsoft 365 token cache ──────────────────────────────────
    # The MSAL token cache lives in the user profile — check its age and size
    # If it's been cleared or corrupted, Word/Outlook show "Sign in required"
    ps_onedrive = r"""
$result = @{}

# Helper: a process is truly suspended when at least one thread has WaitReason = Suspended
# (NOT just ThreadState = Wait — that is normal for any idle process)
function Test-ProcessSuspended($proc) {
    try {
        $suspThreads = $proc.Threads | Where-Object {
            $_.ThreadState -eq [System.Diagnostics.ThreadState]::Wait -and
            $_.WaitReason  -eq [System.Diagnostics.ThreadWaitReason]::Suspended
        }
        return ($suspThreads.Count -gt 0)
    } catch { return $false }
}

# OneDrive process - check running AND truly suspended
$odProc = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
$result.OneDriveRunning   = ($null -ne $odProc)
$result.OneDriveSuspended = $false
$result.OneDrivePriority  = ""
if ($odProc) {
    try {
        $result.OneDriveSuspended = Test-ProcessSuspended $odProc
        $result.OneDrivePriority  = $odProc.PriorityClass.ToString()
    } catch {}
}

# Check other auth-related processes for true suspension
$authProcs = @("olk", "WWAHost")
$suspendedAuth = @()
foreach ($pname in $authProcs) {
    Get-Process -Name $pname -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-ProcessSuspended $_) {
            $suspendedAuth += [PSCustomObject]@{ Name = $_.ProcessName; PID = $_.Id }
        }
    }
}
$result.SuspendedAuthProcs  = $suspendedAuth
$result.BrokerIssues        = @()
$result.MsAccountSuspended  = $false

# OneDrive sync status via registry
try {
    $odStatus = Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal" `
        -ErrorAction Stop
    $result.OneDriveAccount   = $odStatus.UserEmail
    $result.OneDriveConnected = ($null -ne $odStatus.UserEmail -and $odStatus.UserEmail -ne "")
} catch {
    try {
        $odBiz = Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1" `
            -ErrorAction Stop
        $result.OneDriveAccount   = $odBiz.UserEmail
        $result.OneDriveConnected = ($null -ne $odBiz.UserEmail)
    } catch {
        $result.OneDriveAccount   = $null
        $result.OneDriveConnected = $false
    }
}

# MSAL token cache — Office apps store OAuth tokens here
$msalPath = "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"
if (Test-Path $msalPath) {
    $files = Get-ChildItem $msalPath -Recurse -ErrorAction SilentlyContinue
    $result.MsalCacheFiles = $files.Count
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $result.MsalCacheNewest = if ($newest) { $newest.LastWriteTime.ToString("o") } else { $null }
    $result.MsalCacheSizeKB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1KB, 1)
} else {
    $result.MsalCacheFiles  = 0
    $result.MsalCacheNewest = $null
    $result.MsalCacheSizeKB = 0
}

# Office credential locations in Credential Manager
$officeCreds = cmdkey /list 2>$null | Where-Object {
    $_ -match "MicrosoftOffice|OneDrive|SharePoint|microsoftonline|live\.com|outlook"
}
$result.OfficeCreds = @($officeCreds | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

# Last Office/OneDrive error events
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName="Application"
        ProviderName=@("Microsoft Office","OneDrive","MSOIDSVC")
        Level=@(1,2,3)
    } -MaxEvents 10 -ErrorAction Stop
    $result.OfficeErrors = @($evts | ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated.ToString("o")
            Source  = $_.ProviderName
            Message = if ($_.Message) { $_.Message.Substring(0,[Math]::Min(150,$_.Message.Length)) } else { "" }
        }
    })
} catch { $result.OfficeErrors = @() }

$result | ConvertTo-Json -Depth 3
"""

    # ── Fast Startup ───────────────────────────────────────────────────────────
    ps_fast = r"""
try {
    $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
        -Name "HiberbootEnabled" -ErrorAction Stop).HiberbootEnabled
    [PSCustomObject]@{ FastStartupEnabled = ($val -eq 1) } | ConvertTo-Json
} catch { '{"FastStartupEnabled": null}' }
"""

    # ── Recent credential failure events (Security log 4625 = failed logon) ───
    ps_events = r"""
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=@(4625,4648,4776)
    } -MaxEvents 50 -ErrorAction Stop
    $evts | ForEach-Object {
        [PSCustomObject]@{
            Id          = $_.Id
            Time        = $_.TimeCreated.ToString('o')
            Message     = if ($_.Message) { $_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) } else { "" }
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    # ── SMB firewall rule check ────────────────────────────────────────────────
    ps_fw = r"""
try {
    $rules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction Stop |
             Select-Object DisplayName, Enabled, Action, Direction
    $rules | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    import concurrent.futures

    list_keys = {"creds", "events", "fw"}

    def _run_ps(name, ps):
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=25
            )
            raw = r.stdout.strip()
            return name, json.loads(raw) if raw and raw not in ("", "[]", "{}") else ([] if name in list_keys else {})
        except Exception as e:
            print(f"[CredNet] {name} error: {e}")
            return name, [] if name in list_keys else {}

    results = {}
    scripts = [
        ("creds", ps_creds),
        ("smb", ps_smb),
        ("onedrive", ps_onedrive),
        ("fast", ps_fast),
        ("events", ps_events),
        ("fw", ps_fw),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run_ps, n, ps): n for n, ps in scripts}
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            try:
                name, data = fut.result()
                results[name] = data
            except Exception as e:
                fallback_name = futures[fut]
                print(f"[CredNet] {fallback_name} error: {e}")
                results[fallback_name] = [] if fallback_name in list_keys else {}

    creds = results.get("creds", [])
    smb = results.get("smb", {})
    onedrive = results.get("onedrive", {})
    fast = results.get("fast", {})
    events = results.get("events", [])
    fw = results.get("fw", [])
    if isinstance(creds, dict):
        creds = [creds]
    if isinstance(events, dict):
        events = [events]
    if isinstance(fw, dict):
        fw = [fw]

    # Categorise credentials
    email_creds = [
        c
        for c in creds
        if any(
            w in str(c.get("Target", "")).lower()
            for w in (
                "outlook",
                "office",
                "microsoft",
                "smtp",
                "imap",
                "exchange",
                "gmail",
                "yahoo",
                "icloud",
                "microsoftonline",
                "live.com",
            )
        )
    ]
    nas_creds = [
        c
        for c in creds
        if any(
            w in str(c.get("Target", "")).lower()
            for w in ("smb", "nas", "share", "synology", "qnap", "wd", "netgear", "cifs", "nfs")
        )
    ]

    # Drives - SMB/CIFS/NFS
    drives = smb.get("MappedDrives", []) if isinstance(smb, dict) else []
    drives_down = [d for d in drives if not d.get("Reachable", True)]
    drives_up = [d for d in drives if d.get("Reachable", True)]
    smb_drives = [d for d in drives if "SMB" in d.get("Protocol", "")]
    nfs_drives = [d for d in drives if "NFS" in d.get("Protocol", "")]
    nfs_mounts = smb.get("NfsMounts", []) if isinstance(smb, dict) else []

    # OneDrive / M365 token status
    od_running = onedrive.get("OneDriveRunning", False) if isinstance(onedrive, dict) else False
    od_connected = onedrive.get("OneDriveConnected", False) if isinstance(onedrive, dict) else False
    od_account = onedrive.get("OneDriveAccount", "") if isinstance(onedrive, dict) else ""
    msal_files = onedrive.get("MsalCacheFiles", 0) if isinstance(onedrive, dict) else 0
    msal_newest = onedrive.get("MsalCacheNewest") if isinstance(onedrive, dict) else None
    msal_size = onedrive.get("MsalCacheSizeKB", 0) if isinstance(onedrive, dict) else 0
    office_creds = onedrive.get("OfficeCreds", []) if isinstance(onedrive, dict) else []
    office_errors = onedrive.get("OfficeErrors", []) if isinstance(onedrive, dict) else []

    # Token age - flag if MSAL token older than 8 hours
    token_stale = False
    token_age_h = None
    if msal_newest:
        try:
            token_dt = _parse_ts(msal_newest)
            token_age_h = round((datetime.now(timezone.utc) - token_dt).total_seconds() / 3600, 1)
            token_stale = token_age_h > 8
        except Exception:
            pass

    # Credential events
    cred_failures = [e for e in events if e.get("Id") in (4625, 4776)]
    cred_explicit = [e for e in events if e.get("Id") == 4648]
    fast_startup = fast.get("FastStartupEnabled")
    fw_blocking = [f for f in fw if f.get("Action", "") == "Block" and f.get("Enabled")]

    return {
        "creds": creds,
        "email_creds": email_creds,
        "nas_creds": nas_creds,
        "drives": drives,
        "drives_down": drives_down,
        "drives_up": drives_up,
        "smb_drives": smb_drives,
        "nfs_drives": nfs_drives,
        "nfs_mounts": nfs_mounts,
        "smb_connections": smb.get("SmbConnections", []) if isinstance(smb, dict) else [],
        "smb_config": smb.get("SmbConfig") if isinstance(smb, dict) else None,
        "fast_startup": fast_startup,
        "cred_failures": cred_failures[:10],
        "cred_explicit": cred_explicit[:5],
        "fw_rules": fw,
        "fw_blocking": fw_blocking,
        "total_creds": len(creds),
        "broker_issues": onedrive.get("BrokerIssues", []) if isinstance(onedrive, dict) else [],
        "ms_account_suspended": onedrive.get("MsAccountSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_running": od_running,
        "onedrive_suspended": onedrive.get("OneDriveSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_priority": onedrive.get("OneDrivePriority", "") if isinstance(onedrive, dict) else "",
        "suspended_auth_procs": onedrive.get("SuspendedAuthProcs", []) if isinstance(onedrive, dict) else [],
        "onedrive_connected": od_connected,
        "onedrive_account": od_account,
        "msal_cache_files": msal_files,
        "msal_cache_newest": msal_newest,
        "msal_cache_size_kb": msal_size,
        "msal_token_age_h": token_age_h,
        "msal_token_stale": token_stale,
        "office_creds": office_creds,
        "office_errors": office_errors[:5],
    }


def summarize_credentials_network(data: dict) -> dict:
    insights, actions = [], []
    drives_down = data.get("drives_down", [])
    email_creds = data.get("email_creds", [])
    fast_startup = data.get("fast_startup")
    cred_failures = data.get("cred_failures", [])
    fw_blocking = data.get("fw_blocking", [])
    smb_config = data.get("smb_config")

    # Fast Startup is a known cause of SMB credential loss on reboot
    if fast_startup is True:
        insights.append(
            _insight(
                "warning",
                "Fast Startup is enabled. This is a known cause of SMB share disconnection and "
                "credential loss on reboot. Windows does not fully shut down — network state is "
                "partially preserved in a hibernation file and sometimes restored incorrectly.",
                "Disable Fast Startup: Control Panel > Power Options > Choose what the power "
                "buttons do > Turn on fast startup (uncheck). Then do a full Restart (not Shut Down).",
            )
        )
        actions.append("Disable Fast Startup to fix SMB credential loss on reboot")
    elif fast_startup is False:
        insights.append(_insight("ok", "Fast Startup is disabled. Full shutdown/restart cycle is in effect."))
    else:
        insights.append(_insight("info", "Could not determine Fast Startup state."))

    # Drives down
    if drives_down:
        insights.append(
            _insight(
                "critical",
                f"{len(drives_down)} mapped SMB drive(s) currently unreachable: "
                + ", ".join(f"{d.get('Name', '?')}: ({d.get('DisplayRoot', '')})" for d in drives_down[:3]),
                "Check NAS device is powered on and reachable on the network. Try: net use * /delete then remap.",
            )
        )
        actions.append("Reconnect unreachable SMB drives")
    elif data.get("drives"):
        insights.append(_insight("ok", f"All {len(data['drives'])} mapped SMB drive(s) are reachable."))

    # OneDrive / M365 token status
    token_stale = data.get("msal_token_stale", False)
    token_age = data.get("msal_token_age_h")
    od_running = data.get("onedrive_running", False)
    od_connected = data.get("onedrive_connected", False)
    od_account = data.get("onedrive_account", "")
    office_errs = data.get("office_errors", [])
    # Note: backgroundTaskHost suspensions are typically McAfee's idle UWP RulesEngine —
    # normal Windows behavior, not an auth issue. The real auth issue is OneDrive suspension.
    od_suspended = data.get("onedrive_suspended", False)
    susp_auth = data.get("suspended_auth_procs", [])

    if od_suspended:
        insights.append(
            _insight(
                "critical",
                "OneDrive process is SUSPENDED by Windows memory management. "
                "This is the direct cause of the Sign in Required error in Word and Outlook. "
                "When OneDrive is suspended it cannot refresh Microsoft 365 OAuth tokens.",
                "Fix: run the Resume OneDrive button, or run in PowerShell: "
                "Get-Process OneDrive | ForEach-Object { $_.Threads | ForEach-Object { try { $_.Resume() } catch {} } }. "
                "To prevent recurrence, set OneDrive to AboveNormal priority.",
            )
        )
        actions.append("Resume OneDrive process to fix Office 365 sign-in errors")
    if susp_auth:
        names = ", ".join(p.get("Name", "") for p in susp_auth[:3])
        insights.append(
            _insight(
                "warning",
                f"Other auth-related processes are suspended: {names}. "
                "These may also contribute to Office connectivity issues.",
                "Use the Resume Auth Brokers button to restore them.",
            )
        )

    if token_stale and not od_suspended:
        age_str = f"{token_age:.0f} hours" if token_age else "unknown"
        insights.append(
            _insight(
                "critical",
                f"Microsoft 365 authentication token is {age_str} old. "
                "This is the direct cause of the Sign in Required error in Word and Outlook.",
                "Fix: click the OneDrive cloud icon in the system tray and sign in. "
                "Tokens refresh for all Office apps once signed in.",
            )
        )
        actions.append("Re-sign into OneDrive to fix Office 365 credential expiry")
    elif not od_connected and not od_suspended:
        insights.append(
            _insight(
                "warning",
                "OneDrive is not connected to an account. Office apps will show sign-in prompts.",
                "Click the OneDrive cloud icon in the system tray and sign in.",
            )
        )
    elif not od_running:
        insights.append(
            _insight(
                "warning",
                "OneDrive process is not running. Office credential sync is paused.",
                "Launch OneDrive from the Start menu.",
            )
        )
    else:
        age_str = f" (token refreshed {token_age:.0f}h ago)" if token_age is not None else ""
        acct = f" as {od_account}" if od_account else ""
        insights.append(_insight("ok", f"OneDrive connected{acct}{age_str}."))
    if office_errs:
        insights.append(
            _insight(
                "warning",
                f"{len(office_errs)} recent Office or OneDrive error event(s) in Application log.",
                "Check Event Viewer > Application log for OneDrive and Microsoft Office errors.",
            )
        )

    # NFS/CIFS breakdown
    nfs_drives = data.get("nfs_drives", [])
    if nfs_drives:
        nfs_down = [d for d in nfs_drives if not d.get("Reachable", True)]
        insights.append(
            _insight(
                "critical" if nfs_down else "ok",
                f"{len(nfs_drives)} NFS mount(s): "
                + ", ".join(f"{d.get('Name', '?')} ({d.get('DisplayRoot', '')})" for d in nfs_drives[:3])
                + (f" -- {len(nfs_down)} unreachable" if nfs_down else " -- all reachable"),
            )
        )

    # Email credentials
    if email_creds:
        insights.append(
            _insight(
                "info",
                f"{len(email_creds)} email credential(s) in Credential Manager: "
                + ", ".join(c.get("Target", "")[:40] for c in email_creds[:3]),
                "If Outlook loses these on reboot, check credential Type is Generic not Session.",
            )
        )
    else:
        insights.append(
            _insight(
                "warning",
                "No email credentials in Credential Manager. Outlook uses MSAL token cache only.",
                "Open Credential Manager from Start and check Windows Credentials tab.",
            )
        )

    # Credential failures
    if cred_failures:
        insights.append(
            _insight(
                "warning",
                f"{len(cred_failures)} credential failure event(s) in Security log (Event 4625/4776). "
                "These may correlate with the Outlook and NAS disconnection issues.",
                "Check Security Event Log for the account names and sources involved.",
            )
        )

    # Firewall blocking
    if fw_blocking:
        insights.append(
            _insight(
                "warning",
                "File and Printer Sharing firewall rule(s) set to Block: "
                + ", ".join(f.get("DisplayName", "") for f in fw_blocking[:2]),
                "McAfee may have modified these rules. Check McAfee Firewall settings.",
            )
        )

    # SMB signing
    if smb_config and smb_config.get("RequireSecuritySignature"):
        insights.append(
            _insight(
                "info",
                "SMB security signing is required. If your NAS does not support SMB signing "
                "this can cause intermittent connection failures.",
                "Check NAS SMB settings and ensure SMB2/3 is enabled on the NAS.",
            )
        )

    token_stale = data.get("msal_token_stale", False)
    od_suspended = data.get("onedrive_suspended", False)
    status = (
        "critical"
        if od_suspended or drives_down or token_stale
        else "warning"
        if (fast_startup or cred_failures or fw_blocking or not email_creds)
        else "ok"
    )
    headline = (
        "OneDrive SUSPENDED -- direct cause of Word/Outlook sign-in errors"
        if od_suspended
        else "Office 365 token expired -- re-sign into OneDrive to fix"
        if token_stale
        else f"{len(drives_down)} SMB/CIFS/NFS drive(s) unreachable"
        if drives_down
        else "Fast Startup ON -- likely cause of credential loss on reboot"
        if fast_startup
        else f"{data.get('total_creds', 0)} credentials stored -- connections healthy"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}
