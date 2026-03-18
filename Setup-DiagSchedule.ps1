#Requires -RunAsAdministrator
param()

$TaskName  = "SystemHealthDiagnostic"
$ScriptDir = "C:\shigsapps\windesktopmgr"
$PyExe     = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe"
$Script    = Join-Path $ScriptDir "SystemHealthDiag.py"

if (-not (Test-Path $PyExe)) {
    Write-Host "ERROR: Python not found at $PyExe" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $Script)) {
    Write-Host "ERROR: Script not found at $Script" -ForegroundColor Red
    exit 1
}

Write-Host "Configuring SystemHealthDiagnostic task..." -ForegroundColor Cyan
Write-Host "  Script : $Script"
Write-Host "  Python : $PyExe"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$Action = New-ScheduledTaskAction `
    -Execute $PyExe `
    -Argument "-ExecutionPolicy Bypass `"$Script`"" `
    -WorkingDirectory $ScriptDir

$TriggerDaily = New-ScheduledTaskTrigger -Daily -At "07:00"

$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$TriggerLogon.Delay = "PT2M"

$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -StartWhenAvailable `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -MultipleInstances IgnoreNew

$Principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger @($TriggerDaily, $TriggerLogon) `
    -Settings $Settings `
    -Principal $Principal `
    -Description "Daily system health diagnostic. Runs at 7AM and at login if the scheduled run was missed." `
    -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host ""
    Write-Host "SUCCESS: Task registered with two triggers:" -ForegroundColor Green
    Write-Host "  1. Daily at 7:00 AM"
    Write-Host "  2. At login with 2 minute delay (catches missed overnight runs)"
    Write-Host ""
    Write-Host "StartWhenAvailable is ON - if the machine was off at 7AM," -ForegroundColor Yellow
    Write-Host "the diagnostic runs automatically at next login." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Test now: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
} else {
    Write-Host "ERROR: Task registration failed." -ForegroundColor Red
}


