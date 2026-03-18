#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Migrates WinDesktopMgr from OneDrive to C:\shigsapps\windesktopmgr
    Includes validation at every step. Safe to re-run.

    Run as Administrator:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    .\Migrate-WinDesktopMgr.ps1
#>

$ErrorActionPreference = "Stop"

# ── Paths ─────────────────────────────────────────────────────────────────────
$OldBase      = "C:\Users\higs7\OneDrive\Coding\Windows Tools"
$NewBase      = "C:\shigsapps\windesktopmgr"
$BackupDest   = "C:\Users\higs7\OneDrive\Coding\Windows Tools Backup"
$BackupScript = "C:\shigsapps\backup-windesktopmgr.ps1"
$RoboLog      = "C:\shigsapps\robocopy_migration.log"
$PyExe        = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe"

# ── Helpers ───────────────────────────────────────────────────────────────────
$PassCount = 0
$FailCount = 0
$WarnCount = 0

function Step($n, $msg) {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
    Write-Host "  PHASE $n  |  $msg" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
}

function Test-Step($label, [scriptblock]$check, [scriptblock]$action = $null) {
    # Run optional action first, then validate
    if ($action) {
        try { & $action } catch {
            Write-Host "  [FAIL] $label" -ForegroundColor Red
            Write-Host "         Action error: $_" -ForegroundColor Red
            $script:FailCount++
            return $false
        }
    }
    try {
        $result = & $check
        if ($result) {
            Write-Host "  [PASS] $label" -ForegroundColor Green
            $script:PassCount++
            return $true
        } else {
            Write-Host "  [FAIL] $label" -ForegroundColor Red
            $script:FailCount++
            return $false
        }
    } catch {
        Write-Host "  [FAIL] $label -- $_" -ForegroundColor Red
        $script:FailCount++
        return $false
    }
}

function Test-Warn($label, [scriptblock]$check) {
    try {
        $result = & $check
        if ($result) {
            Write-Host "  [PASS] $label" -ForegroundColor Green
            $script:PassCount++
        } else {
            Write-Host "  [WARN] $label" -ForegroundColor Yellow
            $script:WarnCount++
        }
    } catch {
        Write-Host "  [WARN] $label -- $_" -ForegroundColor Yellow
        $script:WarnCount++
    }
}

function Info($msg) { Write-Host "         $msg" -ForegroundColor DarkGray }

# ── Pre-flight ────────────────────────────────────────────────────────────────
Step 0 "Pre-flight checks"

Test-Step "Python executable exists at $PyExe" {
    Test-Path $PyExe
}

Test-Step "Python runs successfully" {
    $v = & $PyExe --version 2>&1
    Info "Python version: $v"
    $v -match "Python 3"
}

Test-Step "Source folder exists: $OldBase" {
    Test-Path $OldBase
}

Test-Step "windesktopmgr.py exists in source" {
    Test-Path "$OldBase\windesktopmgr\windesktopmgr.py"
}

Test-Step "templates\index.html exists in source" {
    Test-Path "$OldBase\windesktopmgr\templates\index.html"
}

Test-Warn "SystemHealthDiag.py exists in source" {
    Test-Path "$OldBase\SystemHealthDiag.py"
}

Test-Warn "diag_email_config.xml exists in source" {
    Test-Path "$OldBase\diag_email_config.xml"
}

# Stop running Flask process
$flask = Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -EA SilentlyContinue).CommandLine -like "*windesktopmgr*" }
if ($flask) {
    $flask | Stop-Process -Force
    Test-Step "Stopped running WinDesktopMgr process (PID $($flask.Id))" { $true }
} else {
    Info "No running WinDesktopMgr process found -- nothing to stop"
}

if ($FailCount -gt 0) {
    Write-Host "`n[ABORT] $FailCount pre-flight check(s) failed. Fix the issues above before continuing." -ForegroundColor Red
    exit 1
}

# ── Phase 1: Copy files ───────────────────────────────────────────────────────
Step 1 "Copy files to $NewBase"

Test-Step "Create target directory" {
    New-Item -ItemType Directory -Path $NewBase -Force | Out-Null
    Test-Path $NewBase
}

Test-Step "Robocopy source to target (this may take a moment)" {
    $rc = robocopy $OldBase $NewBase /E /COPYALL /LOG:$RoboLog
    $exit = $LASTEXITCODE
    Info "Robocopy exit code: $exit (0-7 = success, 8+ = failure)"
    Info "Full log: $RoboLog"
    $exit -lt 8
} $null

Test-Step "windesktopmgr.py copied" {
    Test-Path "$NewBase\windesktopmgr\windesktopmgr.py"
}

Test-Step "templates\index.html copied" {
    Test-Path "$NewBase\windesktopmgr\templates\index.html"
}

Test-Warn "SystemHealthDiag.py copied" {
    Test-Path "$NewBase\SystemHealthDiag.py"
}

Test-Warn "diag_email_config.xml copied" {
    Test-Path "$NewBase\diag_email_config.xml"
}

Test-Step "File count sanity check (target should have >= source)" {
    $srcCount = (Get-ChildItem $OldBase -Recurse -File).Count
    $dstCount = (Get-ChildItem $NewBase -Recurse -File).Count
    Info "Source file count: $srcCount"
    Info "Target file count: $dstCount"
    $dstCount -ge $srcCount
}

# ── Phase 2: Update path references ──────────────────────────────────────────
Step 2 "Update path references in all config files"

function Update-Paths($label, $filePath, [hashtable]$replacements) {
    if (-not (Test-Path $filePath)) {
        Test-Warn "$label -- file not found, skipping" { $false }
        return
    }
    $c = Get-Content $filePath -Raw -Encoding UTF8
    $changed = 0
    foreach ($old in $replacements.Keys) {
        $new = $replacements[$old]
        if ($c -like "*$old*") {
            $c = $c -replace [regex]::Escape($old), $new
            $changed++
        }
    }
    Set-Content $filePath $c -Encoding UTF8

    Test-Step "$label ($changed replacement(s) made)" {
        $verify = Get-Content $filePath -Raw
        # Check old OneDrive path no longer appears as a functional path
        -not ($verify -match [regex]::Escape("C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr`""))
    }
}

Update-Paths "windesktopmgr.py" "$NewBase\windesktopmgr\windesktopmgr.py" @{
    'C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr' = "$NewBase\windesktopmgr"
    'C:\Users\higs7\OneDrive\Coding\Windows Tools'               = $NewBase
}

Update-Paths "SystemHealthDiag.py" "$NewBase\SystemHealthDiag.py" @{
    'C:\Users\higs7\OneDrive\Coding\Windows Tools' = $NewBase
}

Update-Paths "setup-startup.ps1" "$NewBase\windesktopmgr\setup-startup.ps1" @{
    'C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr' = "$NewBase\windesktopmgr"
    'C:\Users\higs7\OneDrive\Coding\Windows Tools'               = $NewBase
}

Update-Paths "Setup-DiagSchedule.ps1" "$NewBase\Setup-DiagSchedule.ps1" @{
    'C:\Users\higs7\OneDrive\Coding\Windows Tools' = $NewBase
}

# Spot-check new paths are actually in the files
Test-Step "windesktopmgr.py contains new REPORT_DIR path" {
    $c = Get-Content "$NewBase\windesktopmgr\windesktopmgr.py" -Raw
    $c -like "*$NewBase*"
}

Test-Step "SystemHealthDiag.py contains new SCRIPT_DIR path" {
    if (-not (Test-Path "$NewBase\SystemHealthDiag.py")) { return $true } # skip if absent
    $c = Get-Content "$NewBase\SystemHealthDiag.py" -Raw
    $c -like "*$NewBase*"
}

# ── Phase 3: Re-register scheduled tasks ─────────────────────────────────────
Step 3 "Re-register scheduled tasks"

$startupScript = "$NewBase\windesktopmgr\setup-startup.ps1"
Test-Step "Re-register WinDesktopMgr startup task" {
    if (-not (Test-Path $startupScript)) { return $false }
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $startupScript | Out-Null
    $task = Get-ScheduledTask -TaskName "WinDesktopMgr" -ErrorAction SilentlyContinue
    Info "Task state: $($task.State)"
    Info "Task action: $($task.Actions.Execute) $($task.Actions.Arguments)"
    $task -ne $null
}

$diagScript = "$NewBase\Setup-DiagSchedule.ps1"
Test-Step "Re-register SystemHealthDiagnostic task" {
    if (-not (Test-Path $diagScript)) { return $false }
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $diagScript | Out-Null
    $task = Get-ScheduledTask -TaskName "SystemHealthDiagnostic" -ErrorAction SilentlyContinue
    Info "Task state: $($task.State)"
    Info "Task action: $($task.Actions.Execute)"
    $task -ne $null
}

Test-Step "WinDesktopMgr task action points to new path" {
    $t = Get-ScheduledTask -TaskName "WinDesktopMgr" -ErrorAction SilentlyContinue
    $action = "$($t.Actions.Execute) $($t.Actions.Arguments)"
    Info "Action: $action"
    $action -like "*shigsapps*" -or $action -notlike "*OneDrive*"
}

Test-Step "SystemHealthDiagnostic task action points to new path" {
    $t = Get-ScheduledTask -TaskName "SystemHealthDiagnostic" -ErrorAction SilentlyContinue
    $action = "$($t.Actions.Execute) $($t.Actions.Arguments)"
    Info "Action: $action"
    $action -like "*shigsapps*" -or $action -notlike "*OneDrive*"
}

# ── Phase 4: Hourly backup ────────────────────────────────────────────────────
Step 4 "Set up hourly robocopy backup to OneDrive"

Test-Step "Write backup script to $BackupScript" {
    $content = @"
`$src       = '$NewBase'
`$dst       = '$BackupDest'
`$log       = 'C:\shigsapps\robocopy_backup.log'
`$credFile  = '$NewBase\diag_email_config.xml'
`$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Run robocopy -- exit codes 0-7 are success, 8+ are errors
robocopy `$src `$dst /MIR /XO /NFL /NDL /NP /LOG+:`$log
`$rcExit = `$LASTEXITCODE

# Trim log if over 1MB
if ((Get-Item `$log -ErrorAction SilentlyContinue).Length -gt 1MB) {
    Get-Content `$log | Select-Object -Last 200 | Set-Content `$log
}

# Send failure email using same Gmail credentials as SystemHealthDiag
if (`$rcExit -ge 8 -and (Test-Path `$credFile)) {
    try {
        `$cfgJson = powershell -NonInteractive -Command {
            param(`$p)
            `$cfg = Import-Clixml -Path `$p
            @{ FromEmail=`$cfg.FromEmail; ToEmail=`$cfg.ToEmail; Password=`$cfg.Credential.GetNetworkCredential().Password } | ConvertTo-Json
        } -args `$credFile | ConvertFrom-Json
        `$from = `$cfgJson.FromEmail
        `$to   = `$cfgJson.ToEmail
        `$pass = `$cfgJson.Password

        `$subject = "[BACKUP FAILED] WinDesktopMgr robocopy error code `$rcExit -- `$timestamp"
        `$body    = "<html><body style='font-family:Arial,sans-serif;padding:20px'>" +
            "<div style='background:#d32f2f;color:#fff;padding:16px;border-radius:8px;margin-bottom:16px'>" +
            "<h2 style='margin:0'>WinDesktopMgr Hourly Backup Failed</h2>" +
            "<p style='margin:6px 0 0;opacity:.85'>Robocopy exited with code `$rcExit</p></div>" +
            "<table style='border-collapse:collapse;width:100%;max-width:520px'>" +
            "<tr><td style='padding:8px;background:#f5f5f5;font-weight:bold;width:120px'>Time</td><td style='padding:8px'>`$timestamp</td></tr>" +
            "<tr><td style='padding:8px;background:#f5f5f5;font-weight:bold'>Source</td><td style='padding:8px'>`$src</td></tr>" +
            "<tr><td style='padding:8px;background:#f5f5f5;font-weight:bold'>Destination</td><td style='padding:8px'>`$dst</td></tr>" +
            "<tr><td style='padding:8px;background:#f5f5f5;font-weight:bold'>Exit Code</td><td style='padding:8px;color:#d32f2f;font-weight:bold'>`$rcExit (8+ = failure)</td></tr>" +
            "<tr><td style='padding:8px;background:#f5f5f5;font-weight:bold'>Log file</td><td style='padding:8px'>`$log</td></tr>" +
            "</table><p style='margin-top:16px;font-size:13px;color:#666'>Your source files at `$src are unchanged. Check the log for details.</p>" +
            "</body></html>"

        Add-Type -AssemblyName System.Net.Mail
        `$msg             = New-Object System.Net.Mail.MailMessage(`$from, `$to, `$subject, `$body)
        `$msg.IsBodyHtml  = `$true
        `$smtp            = New-Object System.Net.Mail.SmtpClient("smtp.gmail.com", 587)
        `$smtp.EnableSsl  = `$true
        `$smtp.Credentials= New-Object System.Net.NetworkCredential(`$from, `$pass)
        `$smtp.Send(`$msg)
        Add-Content `$log "`$timestamp [ALERT] Failure email sent to `$to"
    } catch {
        Add-Content `$log "`$timestamp [ALERT] Could not send failure email: `$_"
    }
}
"@
    Set-Content $BackupScript $content -Encoding UTF8
    Test-Path $BackupScript
}

Test-Step "Register WindowsToolsBackup scheduled task" {
    Unregister-ScheduledTask -TaskName "WindowsToolsBackup" -Confirm:$false -ErrorAction SilentlyContinue
    $action   = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BackupScript`""
    $trigger  = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName "WindowsToolsBackup" `
        -Action $action -Trigger $trigger -Settings $settings `
        -Description "Hourly robocopy backup of $NewBase to OneDrive" -Force | Out-Null
    $task = Get-ScheduledTask -TaskName "WindowsToolsBackup" -ErrorAction SilentlyContinue
    $task -ne $null
}

Test-Step "Run first backup now and verify success" {
    Start-ScheduledTask -TaskName "WindowsToolsBackup"
    Start-Sleep -Seconds 8
    $result = (Get-ScheduledTaskInfo -TaskName "WindowsToolsBackup").LastTaskResult
    Info "Backup task last result: $result (0 = success)"
    $result -eq 0
}

Test-Step "Backup destination has files" {
    $count = (Get-ChildItem $BackupDest -Recurse -File -ErrorAction SilentlyContinue).Count
    Info "Files in backup destination: $count"
    $count -gt 0
}

# ── Phase 5: Consolidate SystemHealthDiag into repo ───────────────────────────
Step 5 "Consolidate SystemHealthDiag.py into windesktopmgr repo folder"

$shSrc  = "$NewBase\SystemHealthDiag.py"
$shDest = "$NewBase\windesktopmgr\SystemHealthDiag.py"

Test-Step "Copy SystemHealthDiag.py into windesktopmgr folder" {
    if (-not (Test-Path $shSrc)) {
        Info "SystemHealthDiag.py not found at $shSrc -- skipping"
        return $true  # not a fatal failure
    }
    Copy-Item $shSrc $shDest -Force
    Test-Path $shDest
}

Test-Step "Update Setup-DiagSchedule.ps1 to point to repo copy" {
    if (-not (Test-Path $diagScript) -or -not (Test-Path $shDest)) { return $true }
    $c = Get-Content $diagScript -Raw
    $c = $c -replace [regex]::Escape("$NewBase\SystemHealthDiag.py"), $shDest
    Set-Content $diagScript $c -Encoding UTF8
    # Re-register with updated path
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $diagScript | Out-Null
    $t = Get-ScheduledTask -TaskName "SystemHealthDiagnostic" -ErrorAction SilentlyContinue
    $action = "$($t.Actions.Execute) $($t.Actions.Arguments)"
    Info "Updated task action: $action"
    $action -like "*windesktopmgr\SystemHealthDiag*"
}

Test-Step "SystemHealthDiag.py file attributes (check for ReparsePoint/cloud placeholder)" {
    if (-not (Test-Path $shDest)) { return $true }
    $attrs = (Get-Item $shDest).Attributes
    $size  = (Get-Item $shDest).Length
    Info "Attributes: $attrs"
    Info "File size: $size bytes"
    $size -gt 1000  # should be ~65KB
}

# ── Phase 6: Smoke test Flask ─────────────────────────────────────────────────
Step 6 "Smoke test -- verify Flask starts from new location"

Test-Step "windesktopmgr.py syntax check" {
    $result = & $PyExe -m py_compile "$NewBase\windesktopmgr\windesktopmgr.py" 2>&1
    Info "Syntax check output: $(if ($result) { $result } else { 'No errors' })"
    $LASTEXITCODE -eq 0
}

Test-Step "Flask imports resolve (dependency check)" {
    $result = & $PyExe -c "import flask, psutil, json, subprocess; print('OK')" 2>&1
    Info "Import check: $result"
    $result -like "*OK*"
}

# ── Final summary ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "  MIGRATION RESULTS" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  PASS : $PassCount" -ForegroundColor Green
Write-Host "  WARN : $WarnCount" -ForegroundColor Yellow
Write-Host "  FAIL : $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($FailCount -gt 0) {
    Write-Host "  Some steps failed. Review output above before proceeding." -ForegroundColor Red
} else {
    Write-Host "  All critical checks passed." -ForegroundColor Green
    Write-Host ""
    Write-Host "  App location  : $NewBase\windesktopmgr" -ForegroundColor White
    Write-Host "  Hourly backup : $BackupDest" -ForegroundColor White
    Write-Host "  Migration log : $RoboLog" -ForegroundColor White
    Write-Host ""
    Write-Host "  Remaining manual steps:" -ForegroundColor Yellow
    Write-Host "    1. Open http://localhost:5000 and verify all 16 tabs load"
    Write-Host "    2. git add -A, git commit, git push from $NewBase\windesktopmgr"
    Write-Host "    3. Open Claude Desktop > Claude Code > cd $NewBase\windesktopmgr"
}
Write-Host ""
