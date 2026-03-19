#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Wrapper script for the SystemHealthDiagnostic scheduled task.
    Handles log directory creation, output capture, and log rotation.
    Called by the scheduled task via: powershell.exe -File Run-DiagnosticWrapper.ps1
#>

$ScriptDir = "C:\shigsapps\windesktopmgr"
$PyExe     = "C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe"
$Script    = Join-Path $ScriptDir "SystemHealthDiag.py"
$LogDir    = Join-Path $ScriptDir "Logs"

# Ensure Logs directory exists
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Timestamped log file for this run
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile   = Join-Path $LogDir "SystemHealthDiag_$Timestamp.log"

# Run the diagnostic, capturing stdout + stderr to the log file
& $PyExe $Script 2>&1 | Tee-Object -FilePath $LogFile

# Keep only the 7 most recent logs
Get-ChildItem "$LogDir\SystemHealthDiag_*.log" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 7 |
    Remove-Item -Force
