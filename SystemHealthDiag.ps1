#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deep System Health Diagnostic Tool for Windows 11
    Designed for Dell XPS 8960 / Intel i9-14900K
.DESCRIPTION
    Analyzes BSOD causes, system health, drivers, Intel microcode,
    event logs, disk health, memory, and thermals.
    Outputs a self-contained HTML report.
.NOTES
    Run as Administrator: Right-click PowerShell -> Run as Administrator
    Then: .\SystemHealthDiag.ps1
#>

$ErrorActionPreference = "Continue"

# Report output folder and timestamped filename
$ReportFolder = "C:\Users\higs7\OneDrive\Coding\Windows Tools\System Health Reports"
if (-not (Test-Path $ReportFolder)) {
    New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null
}
$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportPath = Join-Path $ReportFolder "SystemHealthReport_$TimeStamp.html"
$DiagData = @{}
$Warnings = [System.Collections.ArrayList]::new()
$Critical = [System.Collections.ArrayList]::new()
$Info = [System.Collections.ArrayList]::new()

Add-Type -AssemblyName System.Web

# Safe string truncation helper
function Safe-Truncate {
    param([string]$Text, [int]$MaxLen = 300)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $clean = $Text -replace "`r`n", " " -replace "`n", " "
    if ($clean.Length -le $MaxLen) { return $clean }
    return $clean.Substring(0, $MaxLen)
}

# HTML encode helper
function HE([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return "" }
    return [System.Web.HttpUtility]::HtmlEncode($s)
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  DEEP SYSTEM HEALTH DIAGNOSTIC TOOL" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Report will be saved to: $ReportPath" -ForegroundColor Gray
Write-Host ""

# ============================================================
# SECTION 1: SYSTEM INFORMATION
# ============================================================
Write-Host "[1/10] Collecting System Information..." -ForegroundColor Yellow

$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$CPU = Get-CimInstance Win32_Processor
$BIOS = Get-CimInstance Win32_BIOS
$BB = Get-CimInstance Win32_BaseBoard

$SysInfo = @{
    ComputerName    = $CS.Name
    Manufacturer    = $CS.Manufacturer
    Model           = $CS.Model
    OSName          = $OS.Caption
    OSVersion       = $OS.Version
    OSBuild         = $OS.BuildNumber
    InstallDate     = $OS.InstallDate.ToString("yyyy-MM-dd")
    LastBoot        = $OS.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
    Uptime          = ((Get-Date) - $OS.LastBootUpTime).ToString("dd\.hh\:mm\:ss")
    CPUName         = $CPU.Name.Trim()
    CPUCores        = $CPU.NumberOfCores
    CPULogical      = $CPU.NumberOfLogicalProcessors
    CPUMaxClock     = "$($CPU.MaxClockSpeed) MHz"
    CPUCurrentClock = "$($CPU.CurrentClockSpeed) MHz"
    BIOSVersion     = $BIOS.SMBIOSBIOSVersion
    BIOSDate        = $BIOS.ReleaseDate.ToString("yyyy-MM-dd")
    Baseboard       = "$($BB.Manufacturer) $($BB.Product) v$($BB.Version)"
    TotalRAM_GB     = [math]::Round($CS.TotalPhysicalMemory / 1GB, 1)
}
$DiagData["SystemInfo"] = $SysInfo

# ============================================================
# SECTION 2: INTEL 13TH/14TH GEN MICROCODE CHECK
# ============================================================
Write-Host "[2/10] Checking Intel CPU Microcode & Known Issues..." -ForegroundColor Yellow

$IntelCheck = @{
    IsAffectedCPU    = $false
    CPUFamily        = "Unknown"
    MicrocodeVersion = "Unknown"
    Recommendation   = ""
    Details          = ""
    BIOSDate         = ""
}

$cpuName = $CPU.Name
if ($cpuName -match "i[579]-1[34]\d{3}") {
    $IntelCheck.IsAffectedCPU = $true
    if ($cpuName -match "i9-14900") {
        $IntelCheck.CPUFamily = "Intel 14th Gen Core i9 (Raptor Lake Refresh)"
    } elseif ($cpuName -match "i7-14700") {
        $IntelCheck.CPUFamily = "Intel 14th Gen Core i7 (Raptor Lake Refresh)"
    } elseif ($cpuName -match "i9-13900") {
        $IntelCheck.CPUFamily = "Intel 13th Gen Core i9 (Raptor Lake)"
    } else {
        $IntelCheck.CPUFamily = "Intel 13th/14th Gen (Potentially Affected)"
    }

    try {
        $mcuPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        $mcuRaw = (Get-ItemProperty -Path $mcuPath -Name "Update Revision" -ErrorAction Stop)."Update Revision"
        if ($mcuRaw -is [byte[]]) {
            $mcuHex = ($mcuRaw | ForEach-Object { "{0:X2}" -f $_ }) -join ""
            $IntelCheck.MicrocodeVersion = "0x$mcuHex"
        } else {
            $IntelCheck.MicrocodeVersion = "$mcuRaw"
        }
    } catch {
        $IntelCheck.MicrocodeVersion = "Unable to read"
    }

    $biosDate = $BIOS.ReleaseDate
    $IntelCheck.BIOSDate = $biosDate.ToString("yyyy-MM-dd")

    if ($biosDate -lt [DateTime]"2024-08-01") {
        [void]$Critical.Add("INTEL CPU VULNERABILITY: Your BIOS date ($($biosDate.ToString('yyyy-MM-dd'))) predates the Intel microcode fix (August 2024). Your i9-14900K may be experiencing eTVB/SVID voltage instability causing BSODs and potential permanent CPU degradation. IMMEDIATE BIOS UPDATE REQUIRED.")
        $IntelCheck.Recommendation = "CRITICAL: Update BIOS immediately to get Intel microcode 0x129 or later. Check Dell support for XPS 8960 BIOS updates."
    } elseif ($biosDate -lt [DateTime]"2024-12-01") {
        [void]$Warnings.Add("INTEL CPU: BIOS has been updated since initial Intel fix but may not have the latest microcode. Verify you have the newest Dell BIOS for XPS 8960.")
        $IntelCheck.Recommendation = "Check for latest Dell BIOS update for XPS 8960 to ensure newest Intel microcode."
    } else {
        [void]$Info.Add("INTEL CPU: BIOS date ($($biosDate.ToString('yyyy-MM-dd'))) is recent and likely includes the Intel microcode fix. However, if the CPU was already degraded before the fix, damage may be irreversible.")
        $IntelCheck.Recommendation = "BIOS appears up to date. If BSODs persist, the CPU may have already sustained degradation. Intel extended their warranty by 2 years for affected 13th/14th Gen CPUs. Visit warranty.intel.com to check status and submit a replacement claim."
    }

    $IntelCheck.Details = "Intel acknowledged that 13th/14th Gen desktop processors (i5/i7/i9) had an elevated operating voltage issue causing instability and permanent degradation. Root causes: eTVB (Enhanced Thermal Velocity Boost) and SVID (Serial VID) algorithms requesting excessive voltage. Intel released microcode 0x129 in August 2024 to mitigate this. CPUs already damaged may need replacement under Intel extended warranty."
} else {
    $IntelCheck.Details = "CPU does not appear to be in the affected Intel 13th/14th Gen desktop family."
    [void]$Info.Add("CPU is not in the known affected Intel 13th/14th Gen range.")
}

$DiagData["IntelCheck"] = $IntelCheck

# ============================================================
# SECTION 3: BSOD / MINIDUMP ANALYSIS
# ============================================================
Write-Host "[3/10] Analyzing BSOD Minidump Files..." -ForegroundColor Yellow

$MiniDumpPath = "$env:SystemRoot\Minidump"
$BSODData = @{
    MinidumpFiles = @()
    BugCheckCodes = @()
    RecentCrashes = 0
    CrashSummary  = @()
    UnexpectedShutdowns = 0
    UnexpectedShutdownDetails = @()
}

if (Test-Path $MiniDumpPath) {
    $dmpFiles = Get-ChildItem -Path $MiniDumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20
    $BSODData.MinidumpFiles = @($dmpFiles | ForEach-Object {
        @{
            FileName = $_.Name
            Date     = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            SizeKB   = [math]::Round($_.Length / 1KB, 1)
        }
    })
    $BSODData.RecentCrashes = @($dmpFiles | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }).Count

    if ($BSODData.RecentCrashes -gt 5) {
        [void]$Critical.Add("HIGH CRASH FREQUENCY: $($BSODData.RecentCrashes) BSOD minidumps in the last 30 days. This indicates a serious ongoing issue.")
    } elseif ($BSODData.RecentCrashes -gt 0) {
        [void]$Warnings.Add("$($BSODData.RecentCrashes) BSOD minidump(s) found in the last 30 days.")
    }
} else {
    [void]$Info.Add("No minidump directory found. Minidumps may be disabled or cleared. Consider enabling: System Properties > Advanced > Startup and Recovery > Small memory dump.")
}

# Parse BugCheck events from System log
$bugChecks = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($bugChecks) {
    foreach ($bc in $bugChecks) {
        $msg = Safe-Truncate $bc.Message 300
        $bugCheckCode = ""
        if ($bc.Message -match "bug check.*?(0x[0-9A-Fa-f]+)") {
            $bugCheckCode = $Matches[1]
        }
        $BSODData.CrashSummary += @{
            Date         = $bc.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            BugCheckCode = $bugCheckCode
            Message      = $msg
        }
        if ($bugCheckCode -and $bugCheckCode -notin $BSODData.BugCheckCodes) {
            $BSODData.BugCheckCodes += $bugCheckCode
        }
    }
}

# Kernel-Power unexpected shutdown (Event 41)
$kernelPower = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; ProviderName='Microsoft-Windows-Kernel-Power'} -MaxEvents 20 -ErrorAction SilentlyContinue
$BSODData.UnexpectedShutdowns = if ($kernelPower) { @($kernelPower).Count } else { 0 }
$BSODData.UnexpectedShutdownDetails = @()
if ($kernelPower) {
    $BSODData.UnexpectedShutdownDetails = @($kernelPower | Select-Object -First 10 | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Message = Safe-Truncate $_.Message 300
        }
    })
}

if ($BSODData.UnexpectedShutdowns -gt 5) {
    [void]$Critical.Add("$($BSODData.UnexpectedShutdowns) unexpected shutdowns (Kernel-Power 41) detected. Combined with BSODs, this points to a hardware or power delivery issue.")
}

$DiagData["BSODData"] = $BSODData

# BugCheck code lookup table
$BugCheckLookup = @{
    "0x0000009C" = "MACHINE_CHECK_EXCEPTION - Hardware failure detected by CPU. Common with degraded Intel 13th/14th gen CPUs."
    "0x00000124" = "WHEA_UNCORRECTABLE_ERROR - Hardware error (often CPU or memory). Strongly associated with Intel voltage degradation."
    "0x0000003B" = "SYSTEM_SERVICE_EXCEPTION - Kernel-mode driver or service fault. Check recently updated drivers."
    "0x0000000A" = "IRQL_NOT_LESS_OR_EQUAL - Driver using improper memory address. Often GPU or network driver."
    "0x0000001E" = "KMODE_EXCEPTION_NOT_HANDLED - Kernel-mode program generated an exception. Check drivers."
    "0x00000050" = "PAGE_FAULT_IN_NONPAGED_AREA - Invalid memory referenced. Can be RAM, driver, or disk issue."
    "0x0000001A" = "MEMORY_MANAGEMENT - Serious memory management error. Run memtest86."
    "0x000000D1" = "DRIVER_IRQL_NOT_LESS_OR_EQUAL - Driver accessed pageable memory at wrong IRQL. Identify the driver."
    "0x00000116" = "VIDEO_TDR_TIMEOUT_DETECTED - GPU driver took too long. Update or rollback GPU driver."
    "0x00000119" = "VIDEO_SCHEDULER_INTERNAL_ERROR - GPU scheduling failure. GPU driver or hardware issue."
    "0x0000007E" = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - System thread threw unhandled exception. Check driver stack."
    "0x000000EF" = "CRITICAL_PROCESS_DIED - Critical system process terminated. Possible file corruption or driver conflict."
    "0x000000C5" = "DRIVER_CORRUPTED_EXPOOL - Driver corrupted pool memory. Faulty driver identified."
    "0x0000009F" = "DRIVER_POWER_STATE_FAILURE - Driver in inconsistent power state. Common during sleep/wake."
    "0x00000133" = "DPC_WATCHDOG_VIOLATION - DPC routine ran too long. Driver performance issue."
    "0x00000139" = "KERNEL_SECURITY_CHECK_FAILURE - Kernel detected data corruption. Can be driver or hardware."
    "0x00000019" = "BAD_POOL_HEADER - Pool header corrupted. Memory or driver issue."
    "0x000000FC" = "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY - Code tried to execute from non-executable memory. Driver bug."
    "0x00000101" = "CLOCK_WATCHDOG_TIMEOUT - Processor not processing interrupts. CPU failure or instability - common with Intel 13/14th gen issue."
    "0x00000154" = "UNEXPECTED_STORE_EXCEPTION - Store component threw unexpected exception. Possible disk or memory."
}
$DiagData["BugCheckLookup"] = $BugCheckLookup

# ============================================================
# SECTION 4: CRITICAL EVENT LOG ANALYSIS
# ============================================================
Write-Host "[4/10] Scanning Windows Event Logs..." -ForegroundColor Yellow

$EventLogData = @{
    SystemCritical  = @()
    SystemErrors    = @()
    AppErrors       = @()
    WHEAErrors      = @()
}

$sysCrit = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1} -MaxEvents 30 -ErrorAction SilentlyContinue
if ($sysCrit) {
    $EventLogData.SystemCritical = @($sysCrit | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Source  = "$($_.ProviderName)"
            EventID = $_.Id
            Message = Safe-Truncate $_.Message 400
        }
    })
}

$sysErr = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 50 -ErrorAction SilentlyContinue
if ($sysErr) {
    $EventLogData.SystemErrors = @($sysErr | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Source  = "$($_.ProviderName)"
            EventID = $_.Id
            Message = Safe-Truncate $_.Message 400
        }
    })
}

$appErr = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 30 -ErrorAction SilentlyContinue
if ($appErr) {
    $EventLogData.AppErrors = @($appErr | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Source  = "$($_.ProviderName)"
            EventID = $_.Id
            Message = Safe-Truncate $_.Message 400
        }
    })
}

$whea = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 50 -ErrorAction SilentlyContinue
if ($whea) {
    $EventLogData.WHEAErrors = @($whea | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID = $_.Id
            Level   = if ($_.LevelDisplayName) { $_.LevelDisplayName } else { "Unknown" }
            Message = Safe-Truncate $_.Message 400
        }
    })
}

if ($EventLogData.WHEAErrors.Count -gt 0) {
    [void]$Critical.Add("$($EventLogData.WHEAErrors.Count) WHEA (hardware error) events found. This strongly indicates a hardware problem - likely CPU, RAM, or motherboard. With an i9-14900K, this is a hallmark of the Intel voltage degradation issue.")
}

$DiagData["EventLogData"] = $EventLogData

# ============================================================
# SECTION 5: DRIVER ANALYSIS
# ============================================================
Write-Host "[5/10] Analyzing Installed Drivers..." -ForegroundColor Yellow

$DriverData = @{
    ProblematicDrivers = @()
    ThirdPartyDrivers  = @()
    OldDrivers         = @()
    TotalDrivers       = 0
}

$allDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverVersion } | Sort-Object DeviceName
$DriverData.TotalDrivers = @($allDrivers).Count

$microsoftPublishers = @("Microsoft", "Microsoft Windows", "Microsoft Corporation")
foreach ($drv in $allDrivers) {
    $isMS = $false
    foreach ($pub in $microsoftPublishers) {
        if ($drv.DriverProviderName -like "*$pub*") { $isMS = $true; break }
    }

    if (-not $isMS -and $drv.DriverProviderName) {
        $entry = @{
            DeviceName  = "$($drv.DeviceName)"
            Provider    = "$($drv.DriverProviderName)"
            Version     = "$($drv.DriverVersion)"
            Date        = if ($drv.DriverDate) { $drv.DriverDate.ToString("yyyy-MM-dd") } else { "Unknown" }
            DeviceClass = "$($drv.DeviceClass)"
            IsSigned    = $drv.IsSigned
        }
        $DriverData.ThirdPartyDrivers += $entry

        if ($drv.DriverDate -and $drv.DriverDate -lt (Get-Date).AddYears(-2)) {
            $DriverData.OldDrivers += $entry
        }
    }
}

$problemDevices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
if ($problemDevices) {
    $DriverData.ProblematicDrivers = @($problemDevices | ForEach-Object {
        @{
            DeviceName = "$($_.Name)"
            DeviceID   = "$($_.DeviceID)"
            ErrorCode  = $_.ConfigManagerErrorCode
            Status     = "$($_.Status)"
        }
    })
}

if ($DriverData.ProblematicDrivers.Count -gt 0) {
    [void]$Warnings.Add("$($DriverData.ProblematicDrivers.Count) device(s) reporting driver errors. These could contribute to system instability.")
}
if ($DriverData.OldDrivers.Count -gt 3) {
    [void]$Warnings.Add("$($DriverData.OldDrivers.Count) third-party drivers are over 2 years old. Outdated drivers can cause BSODs.")
}

$DiagData["DriverData"] = $DriverData

# ============================================================
# SECTION 6: DISK HEALTH
# ============================================================
Write-Host "[6/10] Checking Disk Health..." -ForegroundColor Yellow

$DiskData = @{
    Disks   = @()
    Volumes = @()
    SmartOK = $true
}

$physDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
foreach ($pd in $physDisks) {
    $reliability = $null
    try { $reliability = Get-PhysicalDisk -UniqueId $pd.UniqueId | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
    $disk = @{
        FriendlyName = "$($pd.FriendlyName)"
        MediaType    = "$($pd.MediaType)"
        Size_GB      = [math]::Round($pd.Size / 1GB, 1)
        HealthStatus = "$($pd.HealthStatus)"
        OpStatus     = "$($pd.OperationalStatus)"
        BusType      = "$($pd.BusType)"
        Wear         = if ($reliability -and $reliability.Wear) { "$($reliability.Wear)%" } else { "N/A" }
        Temperature  = if ($reliability -and $reliability.Temperature) { "$($reliability.Temperature)C" } else { "N/A" }
        ReadErrors   = if ($reliability -and $reliability.ReadErrorsTotal) { $reliability.ReadErrorsTotal } else { 0 }
        WriteErrors  = if ($reliability -and $reliability.WriteErrorsTotal) { $reliability.WriteErrorsTotal } else { 0 }
        PowerOnHours = if ($reliability -and $reliability.PowerOnHours) { $reliability.PowerOnHours } else { "N/A" }
    }
    $DiskData.Disks += $disk

    if ($pd.HealthStatus -ne "Healthy") {
        $DiskData.SmartOK = $false
        [void]$Critical.Add("DISK UNHEALTHY: $($pd.FriendlyName) reports status '$($pd.HealthStatus)'. Data loss risk - back up immediately.")
    }
    if ($reliability -and ($reliability.ReadErrorsTotal -gt 0 -or $reliability.WriteErrorsTotal -gt 0)) {
        [void]$Warnings.Add("Disk '$($pd.FriendlyName)' has read/write errors (Read: $($reliability.ReadErrorsTotal), Write: $($reliability.WriteErrorsTotal)).")
    }
}

$volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
$DiskData.Volumes = @($volumes | ForEach-Object {
    $pctFree = if ($_.Size -gt 0) { [math]::Round(($_.SizeRemaining / $_.Size) * 100, 1) } else { 0 }
    if ($_.DriveLetter -eq 'C' -and $pctFree -lt 10) {
        [void]$Warnings.Add("C: drive is critically low on space ($pctFree% free). This can cause system instability and BSODs.")
    }
    @{
        DriveLetter = "$($_.DriveLetter):"
        Label       = "$($_.FileSystemLabel)"
        FileSystem  = "$($_.FileSystem)"
        Size_GB     = [math]::Round($_.Size / 1GB, 1)
        Free_GB     = [math]::Round($_.SizeRemaining / 1GB, 1)
        PercentFree = $pctFree
        Health      = "$($_.HealthStatus)"
    }
})

$DiagData["DiskData"] = $DiskData

# ============================================================
# SECTION 7: MEMORY (RAM) ANALYSIS
# ============================================================
Write-Host "[7/10] Analyzing Memory Configuration..." -ForegroundColor Yellow

$MemData = @{
    Sticks          = @()
    TotalGB         = [math]::Round($CS.TotalPhysicalMemory / 1GB, 1)
    XMPWarning      = $false
    MismatchWarning = $false
}

$ramSticks = Get-CimInstance Win32_PhysicalMemory
$speeds = @()
$sizes = @()
foreach ($stick in $ramSticks) {
    $MemData.Sticks += @{
        BankLabel     = "$($stick.BankLabel)"
        DeviceLocator = "$($stick.DeviceLocator)"
        Capacity_GB   = [math]::Round($stick.Capacity / 1GB, 1)
        Speed_MHz     = $stick.ConfiguredClockSpeed
        Manufacturer  = "$($stick.Manufacturer)"
        PartNumber    = ("$($stick.PartNumber)" -replace '\s+', ' ').Trim()
        FormFactor    = $stick.FormFactor
    }
    $speeds += $stick.ConfiguredClockSpeed
    $sizes += $stick.Capacity
}

if (($speeds | Select-Object -Unique).Count -gt 1) {
    $MemData.MismatchWarning = $true
    $speedList = ($speeds -join ', ')
    [void]$Warnings.Add("RAM sticks are running at different speeds. This can cause instability. Speeds found: $speedList MHz.")
}

if (($sizes | Select-Object -Unique).Count -gt 1) {
    [void]$Warnings.Add("RAM sticks have different capacities. Mismatched RAM can reduce stability.")
}

if ($speeds.Count -gt 0 -and $speeds[0] -gt 5600) {
    $MemData.XMPWarning = $true
    [void]$Warnings.Add("RAM speed ($($speeds[0]) MHz) exceeds Intel official spec for 14th Gen (5600 MHz DDR5). If using XMP/EXPO profiles, try disabling them in BIOS to test stability.")
}

$DiagData["MemData"] = $MemData

# ============================================================
# SECTION 8: TEMPERATURE & POWER
# ============================================================
Write-Host "[8/10] Checking Thermal & Power Status..." -ForegroundColor Yellow

$ThermalData = @{
    CPUThrottling     = $false
    Temperatures      = @()
    PowerPlan         = ""
    CPUPerformancePct = "N/A"
}

$activePlan = powercfg /getactivescheme 2>$null
if ($activePlan) {
    $ThermalData.PowerPlan = ($activePlan -replace 'Power Scheme GUID:\s*\S+\s*\(', '' -replace '\)$', '').Trim()
} else {
    $ThermalData.PowerPlan = "Unknown"
}

try {
    $perfData = Get-Counter '\Processor Information(_Total)\% Processor Performance' -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
    $cpuPerf = [math]::Round($perfData.CounterSamples[0].CookedValue, 1)
    $ThermalData.CPUPerformancePct = $cpuPerf
    if ($cpuPerf -lt 80) {
        [void]$Warnings.Add("CPU performance counter at $cpuPerf%. CPU may be thermal throttling. Check cooling solution.")
        $ThermalData.CPUThrottling = $true
    }
} catch {
    $ThermalData.CPUPerformancePct = "Unable to read"
}

try {
    $thermalZones = Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
    foreach ($tz in $thermalZones) {
        $tempC = [math]::Round(($tz.CurrentTemperature / 10) - 273.15, 1)
        $ThermalData.Temperatures += @{
            Zone  = "$($tz.InstanceName)"
            TempC = $tempC
            TempF = [math]::Round(($tempC * 9/5) + 32, 1)
        }
        if ($tempC -gt 90) {
            [void]$Critical.Add("CPU temperature at ${tempC}C - CRITICALLY HIGH. This will cause throttling and potential damage. Check CPU cooler.")
        } elseif ($tempC -gt 80) {
            [void]$Warnings.Add("CPU temperature at ${tempC}C - elevated. Monitor cooling performance.")
        }
    }
} catch {
    $ThermalData.Temperatures += @{ Zone = "N/A"; TempC = "WMI unavailable"; TempF = "Install HWiNFO64" }
}

$DiagData["ThermalData"] = $ThermalData

# ============================================================
# SECTION 9: WINDOWS UPDATE & SYSTEM FILE INTEGRITY
# ============================================================
Write-Host "[9/10] Checking System Integrity & Updates..." -ForegroundColor Yellow

$IntegrityData = @{
    PendingUpdates  = @()
    UpdateHistory   = @()
    SFCRecommended  = $false
    DISMRecommended = $false
    CBSLogSizeMB    = 0
}

try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $historyCount = $updateSearcher.GetTotalHistoryCount()
    $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 15))
    $IntegrityData.UpdateHistory = @($history | ForEach-Object {
        $resultText = switch ($_.ResultCode) { 2 { "Succeeded" } 3 { "Succeeded with Errors" } 4 { "Failed" } 5 { "Aborted" } default { "In Progress" } }
        @{
            Title  = "$($_.Title)"
            Date   = if ($_.Date) { $_.Date.ToString("yyyy-MM-dd") } else { "Unknown" }
            Result = $resultText
        }
    })

    $failedUpdates = @($IntegrityData.UpdateHistory | Where-Object { $_.Result -eq "Failed" })
    if ($failedUpdates.Count -gt 0) {
        [void]$Warnings.Add("$($failedUpdates.Count) Windows Updates have failed recently. Failed updates can leave the system in an inconsistent state.")
        $IntegrityData.SFCRecommended = $true
    }
} catch {
    $IntegrityData.UpdateHistory = @(@{Title = "Unable to query update history"; Date = ""; Result = ""})
}

$cbsLog = "$env:SystemRoot\Logs\CBS\CBS.log"
if (Test-Path $cbsLog) {
    $IntegrityData.CBSLogSizeMB = [math]::Round((Get-Item $cbsLog).Length / 1MB, 1)
}

$DiagData["IntegrityData"] = $IntegrityData

# ============================================================
# SECTION 10: RELIABILITY MONITOR DATA
# ============================================================
Write-Host "[10/10] Collecting Reliability Data..." -ForegroundColor Yellow

$ReliabilityData = @{
    AppCrashes = @()
    AppHangs   = @()
}

$appCrashes = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; ProviderName='Application Error'} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($appCrashes) {
    $ReliabilityData.AppCrashes = @($appCrashes | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Message = Safe-Truncate $_.Message 400
        }
    })
}

$appHangs = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1002; ProviderName='Application Hang'} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($appHangs) {
    $ReliabilityData.AppHangs = @($appHangs | ForEach-Object {
        @{
            Date    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Message = Safe-Truncate $_.Message 400
        }
    })
}

$DiagData["ReliabilityData"] = $ReliabilityData

# ============================================================
# GENERATE SEVERITY SCORE
# ============================================================
$SeverityScore = 100
$SeverityScore -= ($Critical.Count * 20)
$SeverityScore -= ($Warnings.Count * 5)
$SeverityScore = [Math]::Max(0, [Math]::Min(100, $SeverityScore))

$SeverityLabel = if ($SeverityScore -ge 80) { "Good" }
                 elseif ($SeverityScore -ge 60) { "Fair" }
                 elseif ($SeverityScore -ge 40) { "Poor" }
                 else { "Critical" }

$SeverityColor = if ($SeverityScore -ge 80) { "#22c55e" }
                 elseif ($SeverityScore -ge 60) { "#eab308" }
                 elseif ($SeverityScore -ge 40) { "#f97316" }
                 else { "#ef4444" }

# ============================================================
# BUILD HTML REPORT
# ============================================================
Write-Host ""
Write-Host "Generating HTML Report..." -ForegroundColor Cyan

# --- All dynamic sections use SINGLE-QUOTED strings + concatenation ---
# --- This avoids PowerShell parsing issues with &, (), and special chars ---

# BugCheck codes
$bugCheckHTML = ""
if ($BSODData.BugCheckCodes.Count -gt 0) {
    $bugCheckHTML = '<div class="subsection"><h3>Bug Check Codes Found</h3><div class="code-grid">'
    foreach ($code in $BSODData.BugCheckCodes) {
        $desc = if ($BugCheckLookup.ContainsKey($code)) { $BugCheckLookup[$code] } else { "Unknown bug check code. Analyze minidump with WinDbg for details." }
        $isHWCode = $code -in @("0x0000009C","0x00000124","0x00000101","0x0000001A","0x00000050")
        $badgeClass = if ($isHWCode) { "badge-crit" } else { "badge-warn" }
        $badgeLabel = if ($isHWCode) { "HARDWARE" } else { "SOFTWARE" }
        $descSafe = HE $desc
        $bugCheckHTML += '<div class="code-card"><div class="code-header"><span class="bc-code">' + $code + '</span><span class="badge ' + $badgeClass + '">' + $badgeLabel + '</span></div><p>' + $descSafe + '</p></div>'
    }
    $bugCheckHTML += '</div></div>'
}

# Crash summary
$crashTableHTML = ""
if ($BSODData.CrashSummary.Count -gt 0) {
    $crashTableHTML = '<div class="subsection"><h3>Recent BSOD Events</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Bug Check</th><th>Details</th></tr></thead><tbody>'
    foreach ($c in $BSODData.CrashSummary | Select-Object -First 15) {
        $crashTableHTML += '<tr><td class="nowrap">' + (HE $c.Date) + '</td><td><code>' + (HE $c.BugCheckCode) + '</code></td><td class="msg-cell">' + (HE $c.Message) + '</td></tr>'
    }
    $crashTableHTML += '</tbody></table></div></div>'
}

# Minidumps
$minidumpHTML = ""
if ($BSODData.MinidumpFiles.Count -gt 0) {
    $minidumpHTML = '<div class="subsection"><h3>Minidump Files</h3><p class="help-text">Analyze with <strong>WinDbg</strong> (Microsoft Store): <code>.symfix; .reload; !analyze -v</code></p><div class="table-wrap"><table><thead><tr><th>File</th><th>Date</th><th>Size</th></tr></thead><tbody>'
    foreach ($m in $BSODData.MinidumpFiles) {
        $minidumpHTML += '<tr><td><code>' + (HE $m.FileName) + '</code></td><td class="nowrap">' + (HE $m.Date) + '</td><td>' + (HE $m.SizeKB) + ' KB</td></tr>'
    }
    $minidumpHTML += '</tbody></table></div></div>'
}

# Kernel-Power
$kpHTML = ""
if ($BSODData.UnexpectedShutdowns -gt 0) {
    $shutdownCount = $BSODData.UnexpectedShutdowns
    $kpHTML = '<div class="subsection"><h3>Unexpected Shutdowns - Kernel-Power 41</h3><p>' + $shutdownCount + ' events found -- system lost power or crashed without clean shutdown.</p><div class="table-wrap"><table><thead><tr><th>Date</th><th>Details</th></tr></thead><tbody>'
    foreach ($kp in $BSODData.UnexpectedShutdownDetails) {
        $kpHTML += '<tr><td class="nowrap">' + (HE $kp.Date) + '</td><td class="msg-cell">' + (HE $kp.Message) + '</td></tr>'
    }
    $kpHTML += '</tbody></table></div></div>'
}

# WHEA
$wheaHTML = ""
if ($EventLogData.WHEAErrors.Count -gt 0) {
    $wheaHTML = '<div class="subsection"><h3>WHEA Hardware Errors</h3><p class="alert-inline"><strong>WHEA errors are strong indicators of hardware failure.</strong> With an Intel 13th/14th Gen CPU, these often signal voltage-induced CPU degradation.</p><div class="table-wrap"><table><thead><tr><th>Date</th><th>Event ID</th><th>Level</th><th>Details</th></tr></thead><tbody>'
    foreach ($w in $EventLogData.WHEAErrors | Select-Object -First 20) {
        $lvlClass = if ($w.Level -eq 'Error' -or $w.Level -eq 'Critical') { ' class="err-row"' } else { '' }
        $wheaHTML += '<tr' + $lvlClass + '><td class="nowrap">' + (HE $w.Date) + '</td><td>' + (HE $w.EventID) + '</td><td>' + (HE $w.Level) + '</td><td class="msg-cell">' + (HE $w.Message) + '</td></tr>'
    }
    $wheaHTML += '</tbody></table></div></div>'
}

# System critical
$sysCritHTML = ""
if ($EventLogData.SystemCritical.Count -gt 0) {
    $sysCritHTML = '<div class="subsection"><h3>System Critical Events</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Source</th><th>ID</th><th>Message</th></tr></thead><tbody>'
    foreach ($e in $EventLogData.SystemCritical | Select-Object -First 15) {
        $sysCritHTML += '<tr class="err-row"><td class="nowrap">' + (HE $e.Date) + '</td><td>' + (HE $e.Source) + '</td><td>' + (HE $e.EventID) + '</td><td class="msg-cell">' + (HE $e.Message) + '</td></tr>'
    }
    $sysCritHTML += '</tbody></table></div></div>'
}

# System errors
$sysErrHTML = ""
if ($EventLogData.SystemErrors.Count -gt 0) {
    $sysErrCount = $EventLogData.SystemErrors.Count
    $sysErrHTML = '<div class="subsection"><h3>System Errors - Last 50</h3><details><summary>Click to expand - ' + $sysErrCount + ' events</summary><div class="table-wrap"><table><thead><tr><th>Date</th><th>Source</th><th>ID</th><th>Message</th></tr></thead><tbody>'
    foreach ($e in $EventLogData.SystemErrors) {
        $sysErrHTML += '<tr><td class="nowrap">' + (HE $e.Date) + '</td><td>' + (HE $e.Source) + '</td><td>' + (HE $e.EventID) + '</td><td class="msg-cell">' + (HE $e.Message) + '</td></tr>'
    }
    $sysErrHTML += '</tbody></table></div></details></div>'
}

# Problematic drivers
$drvProbHTML = ""
if ($DriverData.ProblematicDrivers.Count -gt 0) {
    $drvProbHTML = '<div class="subsection"><h3>Devices with Errors</h3><div class="table-wrap"><table><thead><tr><th>Device</th><th>Error Code</th><th>Status</th></tr></thead><tbody>'
    foreach ($d in $DriverData.ProblematicDrivers) {
        $drvProbHTML += '<tr class="err-row"><td>' + (HE $d.DeviceName) + '</td><td>' + (HE $d.ErrorCode) + '</td><td>' + (HE $d.Status) + '</td></tr>'
    }
    $drvProbHTML += '</tbody></table></div></div>'
}

# Third-party drivers
$drv3pHTML = ""
if ($DriverData.ThirdPartyDrivers.Count -gt 0) {
    $drv3pCount = $DriverData.ThirdPartyDrivers.Count
    $drv3pHTML = '<div class="subsection"><h3>Third-Party Drivers - ' + $drv3pCount + '</h3><details><summary>Click to expand</summary><div class="table-wrap"><table><thead><tr><th>Device</th><th>Provider</th><th>Version</th><th>Date</th><th>Signed</th></tr></thead><tbody>'
    foreach ($d in $DriverData.ThirdPartyDrivers | Sort-Object { $_.Date } -Descending) {
        $signedBadge = if ($d.IsSigned) { '<span class="badge badge-ok">Yes</span>' } else { '<span class="badge badge-crit">NO</span>' }
        $drv3pHTML += '<tr><td>' + (HE $d.DeviceName) + '</td><td>' + (HE $d.Provider) + '</td><td><code>' + (HE $d.Version) + '</code></td><td>' + (HE $d.Date) + '</td><td>' + $signedBadge + '</td></tr>'
    }
    $drv3pHTML += '</tbody></table></div></details></div>'
}

# Disks
$diskHTML = '<div class="disk-cards">'
foreach ($d in $DiskData.Disks) {
    $statusClass = if ($d.HealthStatus -eq 'Healthy') { 'status-ok' } else { 'status-bad' }
    $diskHTML += '<div class="disk-card"><div class="disk-card-header"><span class="disk-name">' + (HE $d.FriendlyName) + '</span><span class="badge ' + $statusClass + '">' + (HE $d.HealthStatus) + '</span></div>'
    $diskHTML += '<div class="disk-stats">'
    $diskHTML += '<div><span class="stat-label">Type</span><span class="stat-val">' + (HE $d.MediaType) + '</span></div>'
    $diskHTML += '<div><span class="stat-label">Size</span><span class="stat-val">' + (HE $d.Size_GB) + ' GB</span></div>'
    $diskHTML += '<div><span class="stat-label">Bus</span><span class="stat-val">' + (HE $d.BusType) + '</span></div>'
    $diskHTML += '<div><span class="stat-label">Wear</span><span class="stat-val">' + (HE $d.Wear) + '</span></div>'
    $diskHTML += '<div><span class="stat-label">Temp</span><span class="stat-val">' + (HE $d.Temperature) + '</span></div>'
    $diskHTML += '<div><span class="stat-label">Power On</span><span class="stat-val">' + (HE $d.PowerOnHours) + ' hrs</span></div>'
    $diskHTML += '<div><span class="stat-label">Read Errors</span><span class="stat-val">' + (HE $d.ReadErrors) + '</span></div>'
    $diskHTML += '<div><span class="stat-label">Write Errors</span><span class="stat-val">' + (HE $d.WriteErrors) + '</span></div>'
    $diskHTML += '</div></div>'
}
$diskHTML += '</div>'

# Volumes
$volHTML = '<div class="table-wrap"><table><thead><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size</th><th>Free</th><th>% Free</th><th>Health</th></tr></thead><tbody>'
foreach ($v in $DiskData.Volumes) {
    $pctClass = if ($v.PercentFree -lt 10) { ' class="err-row"' } elseif ($v.PercentFree -lt 20) { ' class="warn-row"' } else { '' }
    $volHTML += '<tr' + $pctClass + '><td><strong>' + (HE $v.DriveLetter) + '</strong></td><td>' + (HE $v.Label) + '</td><td>' + (HE $v.FileSystem) + '</td><td>' + (HE $v.Size_GB) + ' GB</td><td>' + (HE $v.Free_GB) + ' GB</td><td>' + (HE $v.PercentFree) + '%</td><td>' + (HE $v.Health) + '</td></tr>'
}
$volHTML += '</tbody></table></div>'

# Memory
$memHTML = '<div class="table-wrap"><table><thead><tr><th>Slot</th><th>Size</th><th>Speed</th><th>Manufacturer</th><th>Part Number</th></tr></thead><tbody>'
foreach ($s in $MemData.Sticks) {
    $memHTML += '<tr><td>' + (HE $s.DeviceLocator) + '</td><td>' + (HE $s.Capacity_GB) + ' GB</td><td>' + (HE $s.Speed_MHz) + ' MHz</td><td>' + (HE $s.Manufacturer) + '</td><td><code>' + (HE $s.PartNumber) + '</code></td></tr>'
}
$memHTML += '</tbody></table></div>'

# Thermal
$thermalHTML = '<div class="thermal-grid">'
$thermalHTML += '<div class="thermal-card"><span class="stat-label">Power Plan</span><span class="stat-val">' + (HE $ThermalData.PowerPlan) + '</span></div>'
$thermalHTML += '<div class="thermal-card"><span class="stat-label">CPU Performance</span><span class="stat-val">' + (HE "$($ThermalData.CPUPerformancePct)") + '%</span></div>'
foreach ($t in $ThermalData.Temperatures) {
    $thermalHTML += '<div class="thermal-card"><span class="stat-label">' + (HE $t.Zone) + '</span><span class="stat-val">' + (HE $t.TempC) + 'C / ' + (HE $t.TempF) + 'F</span></div>'
}
$thermalHTML += '</div>'

# Updates
$updateHTML = ""
if ($IntegrityData.UpdateHistory.Count -gt 0) {
    $updateHTML = '<div class="subsection"><h3>Recent Windows Updates</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Result</th><th>Update</th></tr></thead><tbody>'
    foreach ($u in $IntegrityData.UpdateHistory) {
        $rClass = if ($u.Result -eq 'Failed') { ' class="err-row"' } else { '' }
        $updateHTML += '<tr' + $rClass + '><td class="nowrap">' + (HE $u.Date) + '</td><td>' + (HE $u.Result) + '</td><td>' + (HE $u.Title) + '</td></tr>'
    }
    $updateHTML += '</tbody></table></div></div>'
}

# App crashes
$appCrashHTML = ""
if ($ReliabilityData.AppCrashes.Count -gt 0) {
    $appCrashCount = $ReliabilityData.AppCrashes.Count
    $appCrashHTML = '<div class="subsection"><h3>Application Crashes - ' + $appCrashCount + '</h3><details><summary>Click to expand</summary><div class="table-wrap"><table><thead><tr><th>Date</th><th>Details</th></tr></thead><tbody>'
    foreach ($ac in $ReliabilityData.AppCrashes) {
        $appCrashHTML += '<tr><td class="nowrap">' + (HE $ac.Date) + '</td><td class="msg-cell">' + (HE $ac.Message) + '</td></tr>'
    }
    $appCrashHTML += '</tbody></table></div></details></div>'
}

# Findings
$findingsHTML = ""
if ($Critical.Count -gt 0) {
    $findingsHTML += '<div class="findings-group findings-critical"><h3>Critical Issues</h3>'
    foreach ($c in $Critical) {
        $findingsHTML += '<div class="finding-item"><span class="finding-icon">&#9888;</span><p>' + (HE $c) + '</p></div>'
    }
    $findingsHTML += '</div>'
}
if ($Warnings.Count -gt 0) {
    $findingsHTML += '<div class="findings-group findings-warning"><h3>Warnings</h3>'
    foreach ($w in $Warnings) {
        $findingsHTML += '<div class="finding-item"><span class="finding-icon">&#9888;</span><p>' + (HE $w) + '</p></div>'
    }
    $findingsHTML += '</div>'
}
if ($Info.Count -gt 0) {
    $findingsHTML += '<div class="findings-group findings-info"><h3>Informational</h3>'
    foreach ($i in $Info) {
        $findingsHTML += '<div class="finding-item"><span class="finding-icon">&#8505;</span><p>' + (HE $i) + '</p></div>'
    }
    $findingsHTML += '</div>'
}

# Intel section
$intelSectionHTML = ""
if ($IntelCheck.IsAffectedCPU) {
    $intelBorderClass = if ($Critical | Where-Object { $_ -match "INTEL CPU VULNERABILITY" }) { "intel-critical" } else { "intel-warn" }
    $intelSectionHTML = '<div class="intel-box ' + $intelBorderClass + '">'
    $intelSectionHTML += '<h3>Intel 13th/14th Gen Instability Check</h3>'
    $intelSectionHTML += '<div class="intel-grid">'
    $intelSectionHTML += '<div><span class="stat-label">CPU Family</span><span class="stat-val">' + (HE $IntelCheck.CPUFamily) + '</span></div>'
    $intelSectionHTML += '<div><span class="stat-label">Microcode</span><span class="stat-val"><code>' + (HE $IntelCheck.MicrocodeVersion) + '</code></span></div>'
    $intelSectionHTML += '<div><span class="stat-label">BIOS Date</span><span class="stat-val">' + (HE $IntelCheck.BIOSDate) + '</span></div>'
    $intelSectionHTML += '</div>'
    $intelSectionHTML += '<div class="intel-detail"><strong>Background:</strong> ' + (HE $IntelCheck.Details) + '</div>'
    $intelSectionHTML += '<div class="intel-rec"><strong>Recommendation:</strong> ' + (HE $IntelCheck.Recommendation) + '</div>'
    $intelSectionHTML += '<div style="margin-top:1rem;padding:1rem;background:rgba(0,0,0,0.25);border-radius:8px;border:1px solid rgba(255,255,255,0.1);">'
    $intelSectionHTML += '<h4 style="color:var(--text-bright);font-size:0.9rem;margin-bottom:0.6rem;">How to Check Intel Warranty and File a Claim</h4>'
    $intelSectionHTML += '<ol style="padding-left:1.2rem;font-size:0.82rem;color:var(--text);line-height:1.9;">'
    $intelSectionHTML += '<li>Go to <strong>warranty.intel.com</strong> and sign in or create an Intel account</li>'
    $intelSectionHTML += '<li>Click <strong>Check Warranty Status</strong> -- enter your CPU ATPO/batch number (printed on the CPU lid or retail box)</li>'
    $intelSectionHTML += '<li>If you do not have the batch number, download Intel <strong>Processor Diagnostic Tool</strong> from intel.com -- it identifies your CPU serial automatically</li>'
    $intelSectionHTML += '<li>Once warranty is confirmed, click <strong>Submit a Warranty Request</strong></li>'
    $intelSectionHTML += '<li>Select issue type: <strong>System instability / BSOD</strong></li>'
    $intelSectionHTML += '<li>Mention WHEA errors, specific bug check codes from this report, and daily BSOD frequency as evidence</li>'
    $intelSectionHTML += '<li>Intel typically issues an RMA with cross-ship (replacement arrives before you send the old CPU back)</li>'
    $intelSectionHTML += '<li><strong>Alternative:</strong> Contact Dell Support directly -- since this is a Dell XPS 8960, Dell may handle the CPU replacement under their own warranty</li>'
    $intelSectionHTML += '</ol></div>'
    $intelSectionHTML += '</div>'
}

$intelBlockHTML = ""
if ($intelSectionHTML) {
    $intelBlockHTML = @"
    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4A1;</div><h2>Intel CPU Stability Analysis</h2></div>
        <div class="section-body">
            $intelSectionHTML
        </div>
    </div>
"@
}

$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$svgDash = [math]::Round(326.7 * $SeverityScore / 100, 1)

# Pre-compute all counts to avoid $() inside here-string issues
$critCount = $Critical.Count
$warnCount = $Warnings.Count
$infoCount = $Info.Count
$minidumpCount = $BSODData.MinidumpFiles.Count
$recentCrashCount = $BSODData.RecentCrashes
$unexpectedCount = $BSODData.UnexpectedShutdowns
$bcCount = $BSODData.BugCheckCodes.Count
$totalDrvCount = $DriverData.TotalDrivers
$tpDrvCount = $DriverData.ThirdPartyDrivers.Count
$probDrvCount = $DriverData.ProblematicDrivers.Count
$oldDrvCount = $DriverData.OldDrivers.Count
$totalRAM = $MemData.TotalGB
$stickCount = $MemData.Sticks.Count
$mismatchText = if ($MemData.MismatchWarning) { 'YES' } else { 'No' }
$xmpText = if ($MemData.XMPWarning) { 'YES - High Speed' } else { 'No' }
$appCrashTotal = $ReliabilityData.AppCrashes.Count
$appHangTotal = $ReliabilityData.AppHangs.Count
$sysInfoComputer = HE $SysInfo.ComputerName
$sysInfoMfr = HE $SysInfo.Manufacturer
$sysInfoModel = HE $SysInfo.Model
$sysInfoOS = HE $SysInfo.OSName
$sysInfoOSVer = HE $SysInfo.OSVersion
$sysInfoOSBuild = HE $SysInfo.OSBuild
$sysInfoCPU = HE $SysInfo.CPUName
$sysInfoCores = $SysInfo.CPUCores
$sysInfoLogical = $SysInfo.CPULogical
$sysInfoMaxClk = HE $SysInfo.CPUMaxClock
$sysInfoBIOSVer = HE $SysInfo.BIOSVersion
$sysInfoBIOSDate = HE $SysInfo.BIOSDate
$sysInfoBoard = HE $SysInfo.Baseboard
$sysInfoRAM = $SysInfo.TotalRAM_GB
$sysInfoBoot = HE $SysInfo.LastBoot
$sysInfoUptime = HE $SysInfo.Uptime

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>System Health Diagnostic Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600;700&display=swap');
:root {
    --bg: #0a0a0f; --bg-card: #12121a; --bg-card-alt: #181825;
    --border: #2a2a3a; --border-light: #3a3a4f;
    --text: #e4e4ef; --text-dim: #8888a0; --text-bright: #ffffff;
    --accent: #6c8aff; --accent-glow: rgba(108,138,255,0.15);
    --red: #ff4d6a; --red-bg: rgba(255,77,106,0.08); --red-border: rgba(255,77,106,0.25);
    --orange: #ff9f43; --orange-bg: rgba(255,159,67,0.08); --orange-border: rgba(255,159,67,0.25);
    --green: #22c55e; --green-bg: rgba(34,197,94,0.08); --green-border: rgba(34,197,94,0.25);
    --blue-bg: rgba(108,138,255,0.08); --blue-border: rgba(108,138,255,0.25);
    --font: 'DM Sans', -apple-system, sans-serif; --mono: 'JetBrains Mono', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.header { text-align: center; padding: 3rem 0 2rem; border-bottom: 1px solid var(--border); margin-bottom: 2.5rem; }
.header h1 { font-size: 2rem; font-weight: 700; color: var(--text-bright); letter-spacing: -0.5px; margin-bottom: 0.5rem; }
.header .subtitle { color: var(--text-dim); font-size: 0.95rem; }
.header .sys-badge { display: inline-block; margin-top: 1rem; padding: 0.4rem 1rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; font-family: var(--mono); font-size: 0.8rem; color: var(--accent); }
.score-section { display: flex; align-items: center; gap: 2rem; padding: 2rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 2rem; }
.score-ring { position: relative; width: 120px; height: 120px; flex-shrink: 0; }
.score-ring svg { transform: rotate(-90deg); }
.score-ring .score-num { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; font-weight: 700; color: var(--text-bright); }
.score-ring .score-label { position: absolute; top: 68%; left: 50%; transform: translate(-50%, 0); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); }
.score-details h2 { font-size: 1.3rem; color: var(--text-bright); margin-bottom: 0.3rem; }
.score-details p { color: var(--text-dim); font-size: 0.9rem; }
.score-counts { display: flex; gap: 1rem; margin-top: 0.8rem; }
.score-counts span { font-size: 0.8rem; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: 600; }
.cnt-crit { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
.cnt-warn { background: var(--orange-bg); color: var(--orange); border: 1px solid var(--orange-border); }
.cnt-info { background: var(--blue-bg); color: var(--accent); border: 1px solid var(--blue-border); }
.section { margin-bottom: 2rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.section-header { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.75rem; }
.section-header h2 { font-size: 1.1rem; font-weight: 600; color: var(--text-bright); }
.section-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: var(--accent-glow); border-radius: 8px; font-size: 1rem; }
.section-body { padding: 1.5rem; }
.subsection { margin-bottom: 1.5rem; }
.subsection:last-child { margin-bottom: 0; }
.subsection h3 { font-size: 0.95rem; font-weight: 600; color: var(--text-bright); margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
.sys-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 0.75rem; }
.sys-item { display: flex; justify-content: space-between; padding: 0.6rem 0.8rem; background: var(--bg-card-alt); border-radius: 6px; border: 1px solid var(--border); }
.stat-label { font-size: 0.8rem; color: var(--text-dim); }
.stat-val { font-size: 0.85rem; color: var(--text-bright); font-weight: 500; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { text-align: left; padding: 0.6rem 0.75rem; background: var(--bg-card-alt); color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); position: sticky; top: 0; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); color: var(--text); vertical-align: top; }
tr:hover td { background: rgba(108,138,255,0.03); }
.err-row td { background: var(--red-bg); }
.warn-row td { background: var(--orange-bg); }
.nowrap { white-space: nowrap; }
.msg-cell { max-width: 500px; word-break: break-word; font-size: 0.78rem; color: var(--text-dim); }
code { font-family: var(--mono); font-size: 0.8rem; background: var(--bg-card-alt); padding: 0.1rem 0.4rem; border-radius: 3px; color: var(--accent); }
.badge { display: inline-block; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 0.2rem 0.5rem; border-radius: 4px; }
.badge-crit { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
.badge-warn { background: var(--orange-bg); color: var(--orange); border: 1px solid var(--orange-border); }
.badge-ok, .status-ok { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
.status-bad { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
.code-grid { display: grid; gap: 0.75rem; }
.code-card { padding: 1rem; background: var(--bg-card-alt); border: 1px solid var(--border); border-radius: 8px; }
.code-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
.bc-code { font-family: var(--mono); font-size: 1.1rem; font-weight: 700; color: var(--text-bright); }
.code-card p { font-size: 0.85rem; color: var(--text-dim); line-height: 1.5; }
.intel-box { padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem; }
.intel-critical { background: var(--red-bg); border: 2px solid var(--red-border); }
.intel-warn { background: var(--orange-bg); border: 2px solid var(--orange-border); }
.intel-box h3 { font-size: 1.1rem; color: var(--text-bright); margin-bottom: 1rem; }
.intel-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.75rem; margin-bottom: 1rem; }
.intel-grid > div { display: flex; flex-direction: column; gap: 0.2rem; padding: 0.6rem; background: rgba(0,0,0,0.2); border-radius: 6px; }
.intel-detail, .intel-rec { font-size: 0.85rem; color: var(--text); margin-top: 0.75rem; line-height: 1.6; }
.intel-rec { color: var(--text-bright); }
.disk-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
.disk-card { background: var(--bg-card-alt); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.disk-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
.disk-name { font-weight: 600; color: var(--text-bright); }
.disk-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
.disk-stats > div { display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px solid var(--border); }
.thermal-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.75rem; }
.thermal-card { display: flex; flex-direction: column; gap: 0.3rem; padding: 0.8rem; background: var(--bg-card-alt); border: 1px solid var(--border); border-radius: 6px; }
.findings-group { padding: 1.25rem; border-radius: 10px; margin-bottom: 1rem; }
.findings-critical { background: var(--red-bg); border: 1px solid var(--red-border); }
.findings-warning { background: var(--orange-bg); border: 1px solid var(--orange-border); }
.findings-info { background: var(--blue-bg); border: 1px solid var(--blue-border); }
.findings-group h3 { font-size: 0.95rem; margin-bottom: 0.75rem; color: var(--text-bright); }
.finding-item { display: flex; gap: 0.75rem; align-items: flex-start; margin-bottom: 0.6rem; }
.finding-item:last-child { margin-bottom: 0; }
.finding-icon { font-size: 1.1rem; flex-shrink: 0; }
.finding-item p { font-size: 0.85rem; line-height: 1.5; }
.alert-inline { background: var(--red-bg); border: 1px solid var(--red-border); padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.85rem; margin-bottom: 0.75rem; color: var(--text); }
.actions-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 1rem; }
.action-card { padding: 1.25rem; background: var(--bg-card-alt); border: 1px solid var(--border); border-radius: 8px; }
.action-card.action-priority { border-color: var(--red-border); background: var(--red-bg); }
.action-num { width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; background: var(--accent); color: var(--bg); font-weight: 700; font-size: 0.8rem; border-radius: 50%; margin-bottom: 0.75rem; }
.action-priority .action-num { background: var(--red); }
.action-card h4 { font-size: 0.95rem; color: var(--text-bright); margin-bottom: 0.5rem; }
.action-card p { font-size: 0.82rem; color: var(--text-dim); line-height: 1.5; }
.action-card code { font-size: 0.75rem; }
details { margin-top: 0.5rem; }
summary { cursor: pointer; font-size: 0.85rem; color: var(--accent); font-weight: 500; padding: 0.4rem 0; }
summary:hover { text-decoration: underline; }
.help-text { font-size: 0.82rem; color: var(--text-dim); margin-bottom: 0.75rem; }
.footer { text-align: center; padding: 2rem 0; border-top: 1px solid var(--border); margin-top: 2rem; color: var(--text-dim); font-size: 0.8rem; }
@media print { body { background: #fff; color: #111; } .section { border: 1px solid #ccc; break-inside: avoid; } }
@media (max-width: 600px) { .container { padding: 1rem; } .score-section { flex-direction: column; text-align: center; } .sys-grid { grid-template-columns: 1fr; } .actions-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>&#x1F6E1; System Health Diagnostic Report</h1>
        <div class="subtitle">Generated $reportDate</div>
        <div class="sys-badge">$sysInfoMfr $sysInfoModel | $sysInfoCPU | $sysInfoRAM GB RAM</div>
    </div>

    <div class="score-section">
        <div class="score-ring">
            <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
                <circle cx="60" cy="60" r="52" fill="none" stroke="$SeverityColor" stroke-width="8"
                    stroke-dasharray="$svgDash 326.7" stroke-linecap="round"/>
            </svg>
            <div class="score-num">$SeverityScore</div>
            <div class="score-label">$SeverityLabel</div>
        </div>
        <div class="score-details">
            <h2>Overall System Health</h2>
            <p>Based on analysis of event logs, drivers, hardware status, BSOD history, and Intel CPU microcode.</p>
            <div class="score-counts">
                <span class="cnt-crit">$critCount Critical</span>
                <span class="cnt-warn">$warnCount Warnings</span>
                <span class="cnt-info">$infoCount Info</span>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F50D;</div><h2>Key Findings</h2></div>
        <div class="section-body">$findingsHTML</div>
    </div>

    $intelBlockHTML

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4A5;</div><h2>BSOD / Crash Analysis</h2></div>
        <div class="section-body">
            <div class="subsection">
                <div class="sys-grid">
                    <div class="sys-item"><span class="stat-label">Minidump Files</span><span class="stat-val">$minidumpCount</span></div>
                    <div class="sys-item"><span class="stat-label">Crashes - 30 days</span><span class="stat-val">$recentCrashCount</span></div>
                    <div class="sys-item"><span class="stat-label">Unexpected Shutdowns</span><span class="stat-val">$unexpectedCount</span></div>
                    <div class="sys-item"><span class="stat-label">Bug Check Codes</span><span class="stat-val">$bcCount unique</span></div>
                </div>
            </div>
            $bugCheckHTML
            $crashTableHTML
            $kpHTML
            $minidumpHTML
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4CB;</div><h2>Event Log Analysis</h2></div>
        <div class="section-body">
            $wheaHTML
            $sysCritHTML
            $sysErrHTML
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x2699;</div><h2>Driver Analysis</h2></div>
        <div class="section-body">
            <div class="subsection">
                <div class="sys-grid">
                    <div class="sys-item"><span class="stat-label">Total Drivers</span><span class="stat-val">$totalDrvCount</span></div>
                    <div class="sys-item"><span class="stat-label">Third-Party</span><span class="stat-val">$tpDrvCount</span></div>
                    <div class="sys-item"><span class="stat-label">With Errors</span><span class="stat-val">$probDrvCount</span></div>
                    <div class="sys-item"><span class="stat-label">Outdated - 2yr+</span><span class="stat-val">$oldDrvCount</span></div>
                </div>
            </div>
            $drvProbHTML
            $drv3pHTML
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4BE;</div><h2>Disk Health</h2></div>
        <div class="section-body">
            $diskHTML
            <div class="subsection"><h3>Volumes</h3>$volHTML</div>
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F9E0;</div><h2>Memory - RAM</h2></div>
        <div class="section-body">
            <div class="subsection">
                <div class="sys-grid">
                    <div class="sys-item"><span class="stat-label">Total RAM</span><span class="stat-val">$totalRAM GB</span></div>
                    <div class="sys-item"><span class="stat-label">Sticks Installed</span><span class="stat-val">$stickCount</span></div>
                    <div class="sys-item"><span class="stat-label">Speed Mismatch</span><span class="stat-val">$mismatchText</span></div>
                    <div class="sys-item"><span class="stat-label">XMP Concern</span><span class="stat-val">$xmpText</span></div>
                </div>
            </div>
            <div class="subsection"><h3>Installed Modules</h3>$memHTML</div>
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F321;</div><h2>Thermal and Power</h2></div>
        <div class="section-body">$thermalHTML</div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4BB;</div><h2>System Information</h2></div>
        <div class="section-body">
            <div class="sys-grid">
                <div class="sys-item"><span class="stat-label">Computer</span><span class="stat-val">$sysInfoComputer</span></div>
                <div class="sys-item"><span class="stat-label">Model</span><span class="stat-val">$sysInfoMfr $sysInfoModel</span></div>
                <div class="sys-item"><span class="stat-label">OS</span><span class="stat-val">$sysInfoOS</span></div>
                <div class="sys-item"><span class="stat-label">OS Build</span><span class="stat-val">$sysInfoOSVer / $sysInfoOSBuild</span></div>
                <div class="sys-item"><span class="stat-label">CPU</span><span class="stat-val">$sysInfoCPU</span></div>
                <div class="sys-item"><span class="stat-label">Cores / Threads</span><span class="stat-val">$sysInfoCores / $sysInfoLogical</span></div>
                <div class="sys-item"><span class="stat-label">Max Clock</span><span class="stat-val">$sysInfoMaxClk</span></div>
                <div class="sys-item"><span class="stat-label">BIOS</span><span class="stat-val">$sysInfoBIOSVer / $sysInfoBIOSDate</span></div>
                <div class="sys-item"><span class="stat-label">Baseboard</span><span class="stat-val">$sysInfoBoard</span></div>
                <div class="sys-item"><span class="stat-label">RAM</span><span class="stat-val">$sysInfoRAM GB</span></div>
                <div class="sys-item"><span class="stat-label">Last Boot</span><span class="stat-val">$sysInfoBoot</span></div>
                <div class="sys-item"><span class="stat-label">Uptime</span><span class="stat-val">$sysInfoUptime</span></div>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F504;</div><h2>Windows Updates and Integrity</h2></div>
        <div class="section-body">
            $updateHTML
            <div class="subsection">
                <h3>Recommended Integrity Checks</h3>
                <p class="help-text">Run these commands in an <strong>Administrator PowerShell</strong> to repair system files:</p>
                <div style="background:var(--bg-card-alt);padding:1rem;border-radius:6px;border:1px solid var(--border);font-family:var(--mono);font-size:0.82rem;line-height:1.8;">
                    sfc /scannow<br>
                    DISM /Online /Cleanup-Image /RestoreHealth<br>
                    chkdsk C: /f /r    <span style="color:var(--text-dim)">(requires reboot)</span>
                </div>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F4CA;</div><h2>Application Reliability</h2></div>
        <div class="section-body">
            <div class="sys-grid" style="margin-bottom:1rem;">
                <div class="sys-item"><span class="stat-label">App Crashes</span><span class="stat-val">$appCrashTotal</span></div>
                <div class="sys-item"><span class="stat-label">App Hangs</span><span class="stat-val">$appHangTotal</span></div>
            </div>
            $appCrashHTML
        </div>
    </div>

    <div class="section">
        <div class="section-header"><div class="section-icon">&#x1F6E0;</div><h2>Recommended Actions</h2></div>
        <div class="section-body">
            <p class="help-text" style="margin-bottom:1rem;">Prioritized steps to resolve BSOD issues. <strong>Red-highlighted steps are highest priority.</strong></p>
            <div class="actions-grid">
                <div class="action-card action-priority">
                    <div class="action-num">1</div>
                    <h4>Update Dell BIOS</h4>
                    <p>Visit <strong>dell.com/support</strong>, enter Service Tag, download and install the latest BIOS for XPS 8960. This is the #1 priority to get the Intel microcode fix.</p>
                </div>
                <div class="action-card action-priority">
                    <div class="action-num">2</div>
                    <h4>Check Intel Warranty and File a Claim</h4>
                    <p>If BSODs persist after BIOS update, your i9-14900K may already be degraded. Intel extended their warranty by 2 additional years for all affected 13th/14th Gen desktop CPUs. Here is how to check and claim:</p>
                    <ol style="margin-top:0.6rem;padding-left:1.2rem;font-size:0.82rem;color:var(--text-dim);line-height:1.8;">
                        <li>Go to <strong>warranty.intel.com</strong></li>
                        <li>Sign in or create an Intel account</li>
                        <li>Click <strong>"Check Warranty Status"</strong> and enter your processor's ATPO/batch number (found printed on the top of the CPU or on the retail box)</li>
                        <li>If you don't have the batch number, use Intel's <strong>Processor Diagnostic Tool</strong> (download from intel.com) -- it will identify your exact CPU and serial</li>
                        <li>Once warranty status is confirmed, click <strong>"Submit a Warranty Request"</strong></li>
                        <li>Select issue type: <strong>"Different different/various BSOD"</strong> or <strong>"System instability"</strong></li>
                        <li>Intel will typically issue an RMA and send a replacement CPU via cross-ship (you get the new one before sending back the old one)</li>
                        <li>If purchased through Dell, you can also contact <strong>Dell Support</strong> directly -- Dell may handle the replacement under their own warranty, which can be faster</li>
                    </ol>
                    <p style="margin-top:0.6rem;"><strong>Key evidence to mention:</strong> WHEA errors in Event Viewer, MACHINE_CHECK_EXCEPTION or WHEA_UNCORRECTABLE_ERROR bug check codes, and daily BSOD frequency.</p>
                </div>
                <div class="action-card">
                    <div class="action-num">3</div>
                    <h4>Run Memory Diagnostics</h4>
                    <p>Open Start menu, type <code>Windows Memory Diagnostic</code> and run it. For deeper testing, download <strong>MemTest86</strong> (free) and run overnight.</p>
                </div>
                <div class="action-card">
                    <div class="action-num">4</div>
                    <h4>Disable XMP in BIOS</h4>
                    <p>If RAM speed exceeds 5600 MHz, enter BIOS (F2 at boot), find XMP/EXPO profile setting, and disable it. Run at JEDEC spec to rule out memory OC issues.</p>
                </div>
                <div class="action-card">
                    <div class="action-num">5</div>
                    <h4>Run SFC and DISM</h4>
                    <p>Open admin PowerShell and run:<br><code>sfc /scannow</code><br>Then: <code>DISM /Online /Cleanup-Image /RestoreHealth</code></p>
                </div>
                <div class="action-card">
                    <div class="action-num">6</div>
                    <h4>Update All Drivers</h4>
                    <p>Visit <strong>dell.com/support</strong> and install all available driver updates. Pay special attention to chipset, GPU, and network drivers.</p>
                </div>
                <div class="action-card">
                    <div class="action-num">7</div>
                    <h4>Analyze Minidumps</h4>
                    <p>Install <strong>WinDbg</strong> from Microsoft Store. Open a .dmp file, run <code>!analyze -v</code> to identify the exact faulting driver/module.</p>
                </div>
                <div class="action-card">
                    <div class="action-num">8</div>
                    <h4>Monitor Temperatures</h4>
                    <p>Install <strong>HWiNFO64</strong> (free). Monitor CPU package temp under load. The i9-14900K should stay below 95C. If higher, reseat cooler or replace thermal paste.</p>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        System Health Diagnostic Tool | Report generated $reportDate | Machine: $sysInfoComputer
    </div>
</div>
</body>
</html>
"@

# Write HTML report
$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  HTML REPORT SAVED" -ForegroundColor Green
Write-Host "  $ReportPath" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

# ============================================================
# PDF CONVERSION (using Microsoft Edge headless)
# ============================================================
$PDFPath = $ReportPath -replace '\.html$', '.pdf'
$edgePath = ""

# Find Edge executable
$edgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:LocalAppData}\Microsoft\Edge\Application\msedge.exe"
)
foreach ($ep in $edgePaths) {
    if (Test-Path $ep) { $edgePath = $ep; break }
}

if ($edgePath) {
    Write-Host ""
    Write-Host "Converting report to PDF..." -ForegroundColor Cyan

    # Edge needs a file:// URI
    $fileUri = "file:///" + ($ReportPath -replace '\\', '/')

    $edgeArgs = "--headless --disable-gpu --no-sandbox --print-to-pdf=`"$PDFPath`" --print-to-pdf-no-header `"$fileUri`""

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $edgePath
    $psi.Arguments = $edgeArgs
    $psi.WindowStyle = 'Hidden'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit(30000)  # 30 second timeout

    if (Test-Path $PDFPath) {
        $pdfSize = [math]::Round((Get-Item $PDFPath).Length / 1KB, 0)
        Write-Host "  PDF created: $PDFPath ($pdfSize KB)" -ForegroundColor Green
    } else {
        Write-Host "  PDF conversion failed -- HTML report is still available" -ForegroundColor Yellow
        $PDFPath = $null
    }
} else {
    Write-Host ""
    Write-Host "Microsoft Edge not found -- skipping PDF conversion" -ForegroundColor Yellow
    Write-Host "HTML report is still available at: $ReportPath" -ForegroundColor Gray
    $PDFPath = $null
}

# ============================================================
# EMAIL REPORT (Gmail SMTP)
# ============================================================
$credFile = Join-Path $PSScriptRoot "diag_email_config.xml"
if (-not $credFile -or -not (Test-Path $credFile)) {
    # Also check common locations
    $altCredFile = "C:\Users\higs7\OneDrive\Coding\Windows Tools\diag_email_config.xml"
    if (Test-Path $altCredFile) { $credFile = $altCredFile }
}

if (Test-Path $credFile) {
    Write-Host ""
    Write-Host "Sending report via email..." -ForegroundColor Cyan

    try {
        $emailConfig = Import-Clixml -Path $credFile

        $smtpServer = "smtp.gmail.com"
        $smtpPort = 587
        $fromEmail = $emailConfig.FromEmail
        $toEmail = $emailConfig.ToEmail
        $appPassword = $emailConfig.Credential.GetNetworkCredential().Password

        # Build email subject with health score
        $scoreTag = if ($SeverityScore -ge 80) { "[OK]" } elseif ($SeverityScore -ge 60) { "[WARN]" } elseif ($SeverityScore -ge 40) { "[POOR]" } else { "[CRITICAL]" }
        $emailSubject = "$scoreTag System Health: $SeverityScore/100 ($SeverityLabel) - $TimeStamp"

        # Build rich HTML email body with full summary
        # -- Critical findings list --
        $critListHTML = ""
        if ($Critical.Count -gt 0) {
            foreach ($c in $Critical) {
                $critListHTML += '<li style="margin-bottom:6px;color:#d32f2f;">' + (HE $c) + '</li>'
            }
        } else {
            $critListHTML = '<li style="color:#388e3c;">None found</li>'
        }

        # -- Warnings list --
        $warnListHTML = ""
        if ($Warnings.Count -gt 0) {
            foreach ($w in $Warnings) {
                $warnListHTML += '<li style="margin-bottom:6px;color:#e65100;">' + (HE $w) + '</li>'
            }
        } else {
            $warnListHTML = '<li style="color:#388e3c;">None found</li>'
        }

        # -- Info list --
        $infoListHTML = ""
        if ($Info.Count -gt 0) {
            foreach ($i in $Info) {
                $infoListHTML += '<li style="margin-bottom:6px;color:#1565c0;">' + (HE $i) + '</li>'
            }
        }

        # -- Bug check summary --
        $bcSummaryHTML = ""
        if ($BSODData.BugCheckCodes.Count -gt 0) {
            $bcSummaryHTML = '<tr><td colspan="2" style="padding:12px 16px;background:#fff3f3;"><strong style="color:#d32f2f;">Bug Check Codes Detected:</strong><ul style="margin:8px 0 0 0;padding-left:20px;">'
            foreach ($code in $BSODData.BugCheckCodes) {
                $desc = if ($BugCheckLookup.ContainsKey($code)) { $BugCheckLookup[$code] } else { "Unknown -- analyze minidump with WinDbg" }
                $bcSummaryHTML += '<li style="margin-bottom:4px;"><strong>' + $code + '</strong> -- ' + (HE $desc) + '</li>'
            }
            $bcSummaryHTML += '</ul></td></tr>'
        }

        # -- Intel CPU status --
        $intelStatusHTML = ""
        if ($IntelCheck.IsAffectedCPU) {
            $intelColor = if ($Critical | Where-Object { $_ -match "INTEL CPU VULNERABILITY" }) { "#d32f2f" } else { "#e65100" }
            $intelStatusHTML = @"
            <tr><td colspan="2" style="padding:12px 16px;background:#fff8e1;">
                <strong style="color:$intelColor;">⚠ Intel 13th/14th Gen CPU Detected</strong><br>
                <span style="font-size:13px;color:#555;">
                    CPU: $($IntelCheck.CPUFamily)<br>
                    Microcode: $($IntelCheck.MicrocodeVersion)<br>
                    BIOS Date: $($IntelCheck.BIOSDate)<br>
                    <strong>Recommendation:</strong> $($IntelCheck.Recommendation)
                </span>
            </td></tr>
"@
        }

        # -- Disk summary --
        $diskSummaryHTML = ""
        foreach ($d in $DiskData.Disks) {
            $dColor = if ($d.HealthStatus -eq 'Healthy') { '#388e3c' } else { '#d32f2f' }
            $diskSummaryHTML += '<span style="color:' + $dColor + ';">' + (HE $d.FriendlyName) + ': ' + (HE $d.HealthStatus) + ' (' + (HE $d.Size_GB) + ' GB ' + (HE $d.MediaType) + ')</span><br>'
        }

        # -- Volume space --
        $volSummaryHTML = ""
        foreach ($v in $DiskData.Volumes) {
            $vColor = if ($v.PercentFree -lt 10) { '#d32f2f' } elseif ($v.PercentFree -lt 20) { '#e65100' } else { '#388e3c' }
            $volSummaryHTML += '<span style="color:' + $vColor + ';">' + (HE $v.DriveLetter) + ' ' + (HE $v.Free_GB) + ' GB free of ' + (HE $v.Size_GB) + ' GB (' + (HE $v.PercentFree) + '% free)</span><br>'
        }

        # -- RAM summary --
        $ramSummaryHTML = ""
        foreach ($s in $MemData.Sticks) {
            $ramSummaryHTML += (HE $s.DeviceLocator) + ': ' + (HE $s.Capacity_GB) + ' GB @ ' + (HE $s.Speed_MHz) + ' MHz (' + (HE $s.Manufacturer) + ')<br>'
        }

        # -- Recent crashes list --
        $recentCrashHTML = ""
        if ($BSODData.CrashSummary.Count -gt 0) {
            foreach ($c in $BSODData.CrashSummary | Select-Object -First 5) {
                $recentCrashHTML += '<li style="margin-bottom:4px;font-size:12px;color:#555;">' + (HE $c.Date) + ' -- <code>' + (HE $c.BugCheckCode) + '</code></li>'
            }
        } else {
            $recentCrashHTML = '<li style="color:#388e3c;">No recent BSOD events recorded</li>'
        }

        # -- Top actions --
        $topActionsHTML = ""
        if ($IntelCheck.IsAffectedCPU) {
            $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Update Dell BIOS</strong> -- dell.com/support -- get the latest Intel microcode fix</li>'
            $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Check Intel Warranty</strong> -- warranty.intel.com -- file for CPU replacement if degraded</li>'
        }
        if ($BSODData.RecentCrashes -gt 0) {
            $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Analyze Minidumps</strong> -- install WinDbg from Microsoft Store, run <code>!analyze -v</code></li>'
        }
        if ($EventLogData.WHEAErrors.Count -gt 0) {
            $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Run Memory Diagnostics</strong> -- Windows Memory Diagnostic or MemTest86</li>'
        }
        if ($MemData.XMPWarning) {
            $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Disable XMP in BIOS</strong> -- RAM speed exceeds Intel spec, test at JEDEC defaults</li>'
        }
        $topActionsHTML += '<li style="margin-bottom:6px;"><strong>Run SFC/DISM</strong> -- <code>sfc /scannow</code> then <code>DISM /Online /Cleanup-Image /RestoreHealth</code></li>'
        if (-not $topActionsHTML) {
            $topActionsHTML = '<li style="color:#388e3c;">System looks healthy -- no urgent actions needed</li>'
        }

        # Score bar color
        $scoreBarColor = if ($SeverityScore -ge 80) { "#4caf50" } elseif ($SeverityScore -ge 60) { "#ff9800" } elseif ($SeverityScore -ge 40) { "#ff5722" } else { "#f44336" }
        $scoreBarWidth = $SeverityScore

        $emailBody = @"
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:640px;margin:20px auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">

    <!-- Header -->
    <div style="background:#1a1a2e;padding:24px 24px 20px;text-align:center;">
        <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:600;">System Health Report</h1>
        <p style="margin:6px 0 0;color:#8888aa;font-size:13px;">$sysInfoMfr $sysInfoModel | $sysInfoCPU | $reportDate</p>
    </div>

    <!-- Score -->
    <div style="padding:20px 24px;text-align:center;border-bottom:1px solid #eee;">
        <div style="font-size:48px;font-weight:700;color:$scoreBarColor;margin-bottom:4px;">$SeverityScore<span style="font-size:20px;color:#999;">/100</span></div>
        <div style="font-size:14px;color:#666;text-transform:uppercase;letter-spacing:1px;">$SeverityLabel</div>
        <div style="margin:12px auto 0;max-width:300px;height:8px;background:#e0e0e0;border-radius:4px;overflow:hidden;">
            <div style="width:${scoreBarWidth}%;height:100%;background:$scoreBarColor;border-radius:4px;"></div>
        </div>
    </div>

    <!-- Quick Stats -->
    <table style="width:100%;border-collapse:collapse;">
        <tr style="background:#fafafa;">
            <td style="padding:10px 16px;border-bottom:1px solid #eee;width:50%;font-size:13px;"><span style="color:#999;">Critical Issues</span><br><strong style="font-size:18px;color:#d32f2f;">$critCount</strong></td>
            <td style="padding:10px 16px;border-bottom:1px solid #eee;width:50%;font-size:13px;"><span style="color:#999;">Warnings</span><br><strong style="font-size:18px;color:#e65100;">$warnCount</strong></td>
        </tr>
        <tr style="background:#fafafa;">
            <td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">BSODs (30 days)</span><br><strong style="font-size:18px;color:#d32f2f;">$recentCrashCount</strong></td>
            <td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">Unexpected Shutdowns</span><br><strong style="font-size:18px;color:#e65100;">$unexpectedCount</strong></td>
        </tr>
        <tr style="background:#fafafa;">
            <td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">WHEA Hardware Errors</span><br><strong style="font-size:18px;color:#d32f2f;">$($EventLogData.WHEAErrors.Count)</strong></td>
            <td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">Problematic Drivers</span><br><strong style="font-size:18px;color:#e65100;">$probDrvCount</strong></td>
        </tr>
        $intelStatusHTML
        $bcSummaryHTML
    </table>

    <!-- Critical Issues -->
    <div style="padding:16px 24px;border-bottom:1px solid #eee;">
        <h2 style="margin:0 0 10px;font-size:15px;color:#d32f2f;">&#9888; Critical Issues</h2>
        <ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;">$critListHTML</ul>
    </div>

    <!-- Warnings -->
    <div style="padding:16px 24px;border-bottom:1px solid #eee;">
        <h2 style="margin:0 0 10px;font-size:15px;color:#e65100;">&#9888; Warnings</h2>
        <ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;">$warnListHTML</ul>
    </div>

    <!-- Recent Crashes -->
    <div style="padding:16px 24px;border-bottom:1px solid #eee;">
        <h2 style="margin:0 0 10px;font-size:15px;color:#333;">Recent BSODs</h2>
        <ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;">$recentCrashHTML</ul>
    </div>

    <!-- Hardware Summary -->
    <div style="padding:16px 24px;border-bottom:1px solid #eee;">
        <h2 style="margin:0 0 10px;font-size:15px;color:#333;">Hardware Summary</h2>
        <table style="width:100%;font-size:13px;line-height:1.7;color:#555;">
            <tr><td style="padding:4px 0;"><strong>Disks:</strong></td><td>$diskSummaryHTML</td></tr>
            <tr><td style="padding:4px 0;"><strong>Volumes:</strong></td><td>$volSummaryHTML</td></tr>
            <tr><td style="padding:4px 0;vertical-align:top;"><strong>RAM ($totalRAM GB):</strong></td><td>$ramSummaryHTML</td></tr>
            <tr><td style="padding:4px 0;"><strong>CPU Perf:</strong></td><td>$($ThermalData.CPUPerformancePct)%$(if ($ThermalData.CPUThrottling) { ' <span style="color:#d32f2f;">(THROTTLING DETECTED)</span>' } else { '' })</td></tr>
            <tr><td style="padding:4px 0;"><strong>Power Plan:</strong></td><td>$($ThermalData.PowerPlan)</td></tr>
            <tr><td style="padding:4px 0;"><strong>Uptime:</strong></td><td>$sysInfoUptime</td></tr>
            <tr><td style="padding:4px 0;"><strong>BIOS:</strong></td><td>$sysInfoBIOSVer ($sysInfoBIOSDate)</td></tr>
        </table>
    </div>

    <!-- Recommended Actions -->
    <div style="padding:16px 24px;border-bottom:1px solid #eee;">
        <h2 style="margin:0 0 10px;font-size:15px;color:#1565c0;">Recommended Next Steps</h2>
        <ol style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;color:#333;">$topActionsHTML</ol>
    </div>

    <!-- Footer -->
    <div style="padding:16px 24px;background:#fafafa;text-align:center;">
        <p style="margin:0;font-size:12px;color:#999;">Full HTML and PDF reports are attached.</p>
        <p style="margin:6px 0 0;font-size:11px;color:#bbb;">System Health Diagnostic Tool | $sysInfoComputer</p>
    </div>

</div>
</body>
</html>
"@

        # Create mail message
        $mailMsg = New-Object System.Net.Mail.MailMessage
        $mailMsg.From = New-Object System.Net.Mail.MailAddress($fromEmail)
        $mailMsg.To.Add($toEmail)
        $mailMsg.Subject = $emailSubject
        $mailMsg.Body = $emailBody
        $mailMsg.IsBodyHtml = $true

        # Attach PDF if available, otherwise HTML
        if ($PDFPath -and (Test-Path $PDFPath)) {
            $mailMsg.Attachments.Add((New-Object System.Net.Mail.Attachment($PDFPath)))
        }
        # Always attach HTML as well
        if (Test-Path $ReportPath) {
            $mailMsg.Attachments.Add((New-Object System.Net.Mail.Attachment($ReportPath)))
        }

        # Send via Gmail SMTP
        $smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
        $smtp.EnableSsl = $true
        $smtp.Credentials = New-Object System.Net.NetworkCredential($fromEmail, $appPassword)
        $smtp.Timeout = 30000  # 30 seconds

        $smtp.Send($mailMsg)

        # Cleanup
        $mailMsg.Dispose()
        $smtp.Dispose()

        Write-Host "  Email sent successfully to $toEmail" -ForegroundColor Green

    } catch {
        Write-Host "  EMAIL FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Check your Gmail App Password and ensure 'Less secure app access' isn't blocking it." -ForegroundColor Yellow
        Write-Host "  The report is still saved locally at: $ReportPath" -ForegroundColor Gray
    }
} else {
    Write-Host ""
    Write-Host "No email configuration found -- skipping email." -ForegroundColor Gray
    Write-Host "Run Setup-DiagSchedule.ps1 to configure daily email reports." -ForegroundColor Gray
}

# ============================================================
# OPEN REPORT (only if running interactively)
# ============================================================
$isInteractive = [Environment]::UserInteractive
if ($isInteractive) {
    Write-Host ""
    Write-Host "Opening report in browser..." -ForegroundColor Cyan
    Start-Process $ReportPath -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "QUICK SUMMARY:" -ForegroundColor Yellow
$scoreColor = if ($SeverityScore -ge 60) { "Green" } else { "Red" }
$critColor = if ($Critical.Count -gt 0) { "Red" } else { "Green" }
$warnColor = if ($Warnings.Count -gt 0) { "Yellow" } else { "Green" }
$crashColor = if ($BSODData.RecentCrashes -gt 0) { "Red" } else { "Green" }
Write-Host "  Health Score: $SeverityScore / 100 ($SeverityLabel)" -ForegroundColor $scoreColor
Write-Host "  Critical Issues: $critCount" -ForegroundColor $critColor
Write-Host "  Warnings: $warnCount" -ForegroundColor $warnColor
Write-Host "  BSOD Minidumps (30d): $recentCrashCount" -ForegroundColor $crashColor
Write-Host ""
