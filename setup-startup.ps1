# WinDesktopMgr — Startup Setup
# Run this once as Administrator to register the app as a login startup task.
# It will launch the Flask server and open the browser automatically on login.

$AppDir   = "C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr"
$PyScript = Join-Path $AppDir "windesktopmgr.py"
$LogFile  = Join-Path $AppDir "windesktopmgr.log"
$BatFile  = Join-Path $AppDir "start-windesktopmgr.bat"
$TaskName = "WinDesktopMgr"

# ── Python executable — full real path (not the WindowsApps Store stub) ───────
# Resolved via: py.exe -c "import sys; print(sys.executable)"
$PyExe = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe"

# ── Sanity checks ──────────────────────────────────────────────────────────────
if (-not (Test-Path $PyExe)) {
    Write-Host "ERROR: Python not found at $PyExe" -ForegroundColor Red
    Write-Host "Run: py.exe -c `"import sys; print(sys.executable)`"  and update `$PyExe." -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $PyScript)) {
    Write-Host "ERROR: Could not find $PyScript" -ForegroundColor Red
    Write-Host "Update `$AppDir at the top of this script and re-run." -ForegroundColor Yellow
    exit 1
}

Write-Host "Python : $PyExe"
Write-Host "Script : $PyScript"
Write-Host "Log    : $LogFile"

# ── Write a .bat launcher — resolves Python at runtime so upgrades don't break it
# Flask is started in the background (start /b), then the browser opens after 6s.
# This is needed because Task Scheduler runs actions sequentially — if Flask ran
# in the foreground it would block forever and the browser would never open.
$batContent = @"
@echo off
cd /d "$AppDir"

:: Resolve Python — prefer py.exe launcher (always points to latest installed)
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "delims=" %%i in ('py.exe -c "import sys; print(sys.executable)"') do set PYEXE=%%i
    goto :run
)

:: Fall back to python.exe on PATH
where python.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=python.exe
    goto :run
)

:: Last resort: hardcoded path from when the task was set up
set PYEXE=$PyExe

:run
echo [%DATE% %TIME%] Starting WinDesktopMgr with: %PYEXE% >> "$LogFile"

:: Start Flask in the background so this script can continue
start /b "" "%PYEXE%" "$PyScript" >> "$LogFile" 2>&1

:: Wait 6 seconds for Flask to bind to port 5000, then open the browser
timeout /t 6 /nobreak >nul
start http://localhost:5000
"@
[System.IO.File]::WriteAllText($BatFile, $batContent, [System.Text.Encoding]::ASCII)
Write-Host "Bat    : $BatFile"

# ── Remove old task if present ────────────────────────────────────────────────
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# ── Single action: .bat handles both Flask (background) + browser open ─────────
$FlaskAction = New-ScheduledTaskAction `
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
    -Action     $FlaskAction `
    -Trigger    $Trigger `
    -Settings   $Settings `
    -Principal  $Principal `
    -Description "Starts WinDesktopMgr Flask server and opens browser on login" `
    -Force | Out-Null

Write-Host ""
Write-Host "SUCCESS: Task '$TaskName' registered." -ForegroundColor Green
Write-Host ""
Write-Host "What happens at login:" -ForegroundColor Cyan
Write-Host "  1. Flask server starts silently in the background"
Write-Host "  2. After 6 seconds, browser opens to http://localhost:5000"
Write-Host "  3. Server output logs to: $LogFile"
Write-Host ""
Write-Host "Test right now (no need to log out):" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host ""
Write-Host "Remove the startup task later:" -ForegroundColor Yellow
Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
