# WinDesktopMgr — Startup Setup
# Run this once as Administrator to register the app as a login startup task.
# Launches the System Tray mode: Flask runs silently, tray icon shows health status,
# toast notifications alert on critical/warning issues.

$AppDir    = "C:\shigsapps\windesktopmgr"
$TrayScript = Join-Path $AppDir "tray.py"
$LogFile   = Join-Path $AppDir "windesktopmgr.log"
$BatFile   = Join-Path $AppDir "start-windesktopmgr.bat"
$TaskName  = "WinDesktopMgr"

# ── Python executable — full real path (not the WindowsApps Store stub) ───────
# Resolved via: py.exe -c "import sys; print(sys.executable)"
$PyExe    = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe"
$PyExeW   = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\pythonw.exe"

# ── Sanity checks ──────────────────────────────────────────────────────────────
if (-not (Test-Path $PyExe)) {
    Write-Host "ERROR: Python not found at $PyExe" -ForegroundColor Red
    Write-Host "Run: py.exe -c `"import sys; print(sys.executable)`"  and update `$PyExe." -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $TrayScript)) {
    Write-Host "ERROR: Could not find $TrayScript" -ForegroundColor Red
    Write-Host "Update `$AppDir at the top of this script and re-run." -ForegroundColor Yellow
    exit 1
}

# Check for pythonw.exe (windowless Python) — fall back to python.exe if missing
if (-not (Test-Path $PyExeW)) {
    Write-Host "WARNING: pythonw.exe not found — using python.exe (console window will be visible)" -ForegroundColor Yellow
    $PyExeW = $PyExe
}

Write-Host "Python  : $PyExeW"
Write-Host "Script  : $TrayScript"
Write-Host "Log     : $LogFile"

# ── Write a .bat launcher — resolves Python at runtime so upgrades don't break it
# Uses pythonw.exe to run tray.py without a console window. The tray app handles
# everything: Flask server, health polling, toast notifications, system tray icon.
$batContent = @"
@echo off
cd /d "$AppDir"

:: Resolve pythonw.exe — prefer py.exe launcher (always points to latest installed)
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "delims=" %%i in ('py.exe -c "import sys, pathlib; print(pathlib.Path(sys.executable).parent / 'pythonw.exe')"') do set PYEXE=%%i
    if exist "%PYEXE%" goto :run
)

:: Fall back to pythonw.exe on PATH
where pythonw.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=pythonw.exe
    goto :run
)

:: Fall back to python.exe on PATH (console will show)
where python.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=python.exe
    goto :run
)

:: Last resort: hardcoded path from when the task was set up
set PYEXE=$PyExeW

:run
echo [%DATE% %TIME%] Starting WinDesktopMgr tray mode with: %PYEXE% >> "$LogFile"

:: Launch tray.py — no console window, tray icon appears in system tray
start /b "" "%PYEXE%" "$TrayScript" >> "$LogFile" 2>&1
"@
[System.IO.File]::WriteAllText($BatFile, $batContent, [System.Text.Encoding]::ASCII)
Write-Host "Bat     : $BatFile"

# ── Remove old task if present ────────────────────────────────────────────────
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# ── Single action: .bat launches tray.py with pythonw.exe ─────────────────────
$TrayAction = New-ScheduledTaskAction `
    -Execute $BatFile `
    -WorkingDirectory $AppDir

# ── Trigger: at login of this user ────────────────────────────────────────────
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"

# ── Settings ───────────────────────────────────────────────────────────────────
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

# ── Principal: interactive session, normal privileges ─────────────────────────
$Principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited

# ── Register ───────────────────────────────────────────────────────────────────
Register-ScheduledTask `
    -TaskName   $TaskName `
    -Action     $TrayAction `
    -Trigger    $Trigger `
    -Settings   $Settings `
    -Principal  $Principal `
    -Description "WinDesktopMgr System Tray — Flask server + health monitoring + toast notifications" `
    -Force | Out-Null

Write-Host ""
Write-Host "SUCCESS: Task '$TaskName' registered." -ForegroundColor Green
Write-Host ""
Write-Host "What happens at login:" -ForegroundColor Cyan
Write-Host "  1. Tray icon appears in the system tray (green/yellow/red)"
Write-Host "  2. Flask server runs silently in the background on port 5000"
Write-Host "  3. Health checks run every 5 minutes"
Write-Host "  4. Toast notifications alert on critical/warning issues"
Write-Host "  5. Right-click tray icon to open dashboard or quit"
Write-Host ""
Write-Host "Test right now (no need to log out):" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host ""
Write-Host "Switch back to browser-only mode:" -ForegroundColor Yellow
Write-Host "  Edit `$TrayScript to `$AppDir\windesktopmgr.py in this script and re-run"
Write-Host ""
Write-Host "Remove the startup task:" -ForegroundColor Yellow
Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"

