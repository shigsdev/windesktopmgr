<#
.SYNOPSIS
    Finish a Storage Spaces drive swap: add the new disk, rebuild parity, then
    (only after the rebuild verifies healthy) drop the old disk's pool entry.

.DESCRIPTION
    Run this AFTER you have physically swapped the drive:
        1. shut down, pull the failed SSD, fit the replacement, boot
        2. run this script from an ELEVATED PowerShell (see EXAMPLE)

    It then does, in order:
        validate  -> exactly one pool, one space, one retired/missing disk,
                     one suitable replacement
        add       -> Add-PhysicalDisk (skipped if a previous run already did it)
        repair    -> Repair-VirtualDisk (parity rebuild; can run for HOURS)
        wait      -> poll the space's storage jobs until the rebuild finishes
        verify    -> the space must be Healthy with OperationalStatus OK
        remove    -> Remove-PhysicalDisk (the old disk's stale pool entry)

    The removal is HARD-GATED on the verification. With PhysicalDiskRedundancy
    = 1, dropping the old disk while the rebuild is incomplete can lose the
    volume, so any failure / suspension / timeout stops BEFORE the removal and
    leaves the pool recoverable. It also refuses to run when anything is
    ambiguous (more than one space in the pool, more than one retired disk,
    more than one poolable replacement) rather than guessing.

    SAFE TO RE-RUN. If an earlier attempt already added the new disk, this
    detects that and resumes at the rebuild instead of demanding a disk you
    have already fitted.

    Requires Administrator: Storage Spaces cmdlets do not work unelevated.

.EXAMPLE
    # Preview only - shows which disk would be added and which removed:
    powershell -ExecutionPolicy Bypass -File .\scripts\repair_storage_pool.ps1 -Preview

.EXAMPLE
    # Do it for real (leave the window open; the rebuild takes hours):
    powershell -ExecutionPolicy Bypass -File .\scripts\repair_storage_pool.ps1
#>
[CmdletBinding()]
param(
    [string]$PoolName = "Storage pool",
    [string]$RetiredSerial = "",
    [string]$StateFile = "",
    [int]$RepairTimeoutHours = 12,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
$PollSeconds = 20
$SuspendedTolerancePolls = 15   # ~5 min: a stale job may resume once space exists
$EmptyPollsToFinish = 3         # parity repair runs in phases with gaps
$script:State = [ordered]@{
    stage = "starting"; ok = $true; done = $false; percent = 0
    message = ""; error = ""; plan = $null
    started = (Get-Date).ToString("o"); updated = (Get-Date).ToString("o")
}

# [IO.File] ignores Set-Location, so resolve -StateFile against the PS location
# once up-front or the .tmp and its destination can land in different folders.
if ($StateFile) {
    $StateFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($StateFile)
}

function Write-State {
    param([string]$Stage, [string]$Message, [int]$Percent = -1, [bool]$Done = $false, [string]$ErrorText = "")
    if ($Stage) { $script:State.stage = $Stage }
    if ($Message) { $script:State.message = $Message }
    if ($Percent -ge 0) { $script:State.percent = $Percent }
    if ($ErrorText) { $script:State.error = $ErrorText; $script:State.ok = $false }
    $script:State.done = $Done
    $script:State.updated = (Get-Date).ToString("o")
    if ($StateFile) {
        try {
            # BOM-less UTF8: Set-Content -Encoding UTF8 on PS 5.1 emits a BOM
            # that breaks JSON readers.
            $json = $script:State | ConvertTo-Json -Depth 5
            [IO.File]::WriteAllText("$StateFile.tmp", $json, [Text.UTF8Encoding]::new($false))
            Move-Item -Path "$StateFile.tmp" -Destination $StateFile -Force
        } catch { }
    }
    $prefix = if ($ErrorText) { "ERROR" } else { $script:State.stage.ToUpper() }
    Write-Host "[$prefix] $($script:State.message)"
}

function Fail {
    param([string]$Text)
    Write-State -Stage "failed" -Message $Text -Done $true -ErrorText $Text
    exit 1
}

# A pool member counts as "gone" when Storage Spaces retired or lost it.
function Test-DiskGone {
    param($Disk)
    if ($Disk.Usage -eq 'Retired') { return $true }
    return (($Disk.OperationalStatus -join ',') -match 'Lost Communication|Unrecognized|Removed')
}

function ConvertTo-SerialKey {
    param([string]$Serial)
    return ($Serial -replace '[^A-Za-z0-9]', '').ToLower()
}

# Jobs for THIS space only. "Storage space" is Windows' default name, so a
# system-wide Get-StorageJob could report an unrelated pool's rebuild.
function Get-SpaceRepairJob {
    param($VirtualDisk)
    $jobs = @()
    try { $jobs = @($VirtualDisk | Get-StorageJob -ErrorAction Stop) } catch {
        $jobs = @(Get-StorageJob -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like "*$($VirtualDisk.FriendlyName)*" })
    }
    return @($jobs | Where-Object { $_.Name -match 'Repair|Regenerat|Rebuild' })
}

function Show-DiskInventory {
    Write-Host ""
    Write-Host "  Disks Windows can see right now:"
    try {
        Get-PhysicalDisk | Select-Object FriendlyName, SerialNumber,
            @{n = 'GB'; e = { [math]::Round($_.Size / 1GB) } }, BusType, CanPool, CannotPoolReason |
            Format-Table -AutoSize | Out-String | Write-Host
    } catch { }
}

try {
    # ── Must be elevated ──────────────────────────────────────────────────────
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Fail "Not elevated. Re-run from an Administrator PowerShell (right-click PowerShell -> Run as administrator)."
    }

    # ── 1. Validate pool + its single space ───────────────────────────────────
    Write-State -Stage "validating" -Message "Checking pool, space, disks" -Percent 0

    $pool = Get-StoragePool -FriendlyName $PoolName -ErrorAction SilentlyContinue
    if (-not $pool) { Fail "Storage pool '$PoolName' not found." }
    if (@($pool).Count -gt 1) { Fail "More than one pool named '$PoolName'." }

    # Remove-PhysicalDisk drops the disk from the WHOLE pool, so every space on
    # it would need rebuilding+verifying. This script verifies one, so it only
    # handles a single-space pool and refuses otherwise.
    $vds = @($pool | Get-VirtualDisk -ErrorAction SilentlyContinue)
    if ($vds.Count -eq 0) { Fail "Pool '$PoolName' has no virtual disk." }
    if ($vds.Count -gt 1) {
        Fail ("Pool '$PoolName' has $($vds.Count) spaces. Removing a disk affects all of them and this " +
              "script only verifies one - repair manually.")
    }
    $vd = $vds[0]
    $initialHealth = "$($vd.HealthStatus)"

    # ── 2. Pick the disk to remove - only ever a retired/missing member ───────
    $members = @($pool | Get-PhysicalDisk -ErrorAction SilentlyContinue)
    $gone = @($members | Where-Object { Test-DiskGone $_ })
    if ($gone.Count -eq 0) { Fail "No retired or missing disk in '$PoolName' - nothing to replace." }
    # A serial may only NARROW the already-retired set; it can never select a
    # healthy member. If one is supplied it must match, or we stop - silently
    # falling back would make the parameter a safety belt that isn't attached.
    if ($RetiredSerial) {
        $want = ConvertTo-SerialKey $RetiredSerial
        if ($want.Length -lt 4) { Fail "-RetiredSerial '$RetiredSerial' is too short to identify a disk." }
        $bySerial = @($gone | Where-Object { (ConvertTo-SerialKey $_.SerialNumber) -eq $want })
        if ($bySerial.Count -ne 1) {
            Fail "-RetiredSerial '$RetiredSerial' matched $($bySerial.Count) retired/missing disks (expected 1)."
        }
        $gone = $bySerial
    }
    if ($gone.Count -gt 1) { Fail "Ambiguous: $($gone.Count) retired/missing disks in '$PoolName'. Resolve manually." }
    $old = $gone[0]
    $oldId = "$($old.UniqueId)"
    if (-not $oldId) { Fail "The retired disk reports no UniqueId - cannot identify it safely." }

    # ── 3. Pick the replacement (or detect a previous run already added it) ───
    # BusType stringified: it can arrive as an enum or a raw UInt16.
    $new = @(Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue |
             Where-Object { "$($_.BusType)" -notin @('USB', 'SD', 'MMC') -and $_.Size -gt 0 })
    $needAdd = $true
    if ($new.Count -eq 0) {
        if ($initialHealth -ne 'Healthy') {
            # Re-run after a failure that happened past the add step: the disk is
            # already in the pool, so resume at the rebuild instead of demanding
            # a drive that is already fitted.
            $needAdd = $false
            Write-State -Stage "validating" -Message ("No unpooled disk found, but the space is '$initialHealth' - " +
                "assuming an earlier run already added the replacement; resuming at the rebuild.")
        } else {
            Show-DiskInventory
            Fail ("No suitable new disk found. Fit the replacement (internal, unpooled). If it is fitted, check " +
                  "the CanPool/CannotPoolReason columns above - a new drive often needs to be brought Online " +
                  "or have an existing partition removed first.")
        }
    } elseif ($new.Count -gt 1) {
        Show-DiskInventory
        Fail "Ambiguous: $($new.Count) poolable disks. Leave only the replacement unpooled."
    } else {
        $new = $new[0]
        # $old.Size is often 0 for a genuinely missing disk, so size the
        # replacement against the smallest surviving member instead.
        $survivorSizes = @($members | Where-Object { -not (Test-DiskGone $_) -and $_.Size -gt 0 } |
                           ForEach-Object { $_.Size })
        $needed = if ($old.Size -gt 0) { $old.Size } elseif ($survivorSizes) { ($survivorSizes | Measure-Object -Minimum).Minimum } else { 0 }
        if ($needed -gt 0 -and $new.Size -lt $needed) {
            Fail ("Replacement ($([math]::Round($new.Size/1GB)) GB) is smaller than the disk it replaces " +
                  "($([math]::Round($needed/1GB)) GB).")
        }
    }

    $script:State.plan = [ordered]@{
        pool = $PoolName; space = "$($vd.FriendlyName)"; resiliency = "$($vd.ResiliencySettingName)"
        add_model = $(if ($needAdd) { "$($new.FriendlyName)" } else { "(already added)" })
        add_serial = $(if ($needAdd) { "$($new.SerialNumber)".Trim() } else { "" })
        remove_model = "$($old.FriendlyName)"; remove_serial = "$($old.SerialNumber)".Trim()
        remove_usage = "$($old.Usage)"
    }
    Write-Host ""
    Write-Host "  Pool    : $PoolName / $($vd.FriendlyName) ($($vd.ResiliencySettingName)) - health $initialHealth"
    if ($needAdd) {
        Write-Host "  ADD     : $($new.FriendlyName)  serial $($new.SerialNumber)  $([math]::Round($new.Size/1GB)) GB"
    } else {
        Write-Host "  ADD     : (skipped - replacement already in the pool)"
    }
    Write-Host "  REMOVE  : $($old.FriendlyName)  serial $($old.SerialNumber)  ($($old.Usage))"
    Write-Host ""

    if ($Preview) {
        Write-State -Stage "preview" -Message "Preview only - nothing was changed." -Done $true
        exit 0
    }

    # ── 4. Add the replacement ────────────────────────────────────────────────
    if ($needAdd) {
        Write-State -Stage "adding" -Message "Adding $($new.FriendlyName) to '$PoolName'" -Percent 5
        Add-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $new -ErrorAction Stop
    }

    # ── 5. Start the parity rebuild ───────────────────────────────────────────
    Write-State -Stage "repairing" -Message "Starting parity rebuild - this can take hours" -Percent 10
    $repairStarted = $true
    try {
        $vd | Repair-VirtualDisk -AsJob -ErrorAction Stop | Out-Null
    } catch {
        $repairStarted = $false
        Write-State -Stage "repairing" -Message "Repair-VirtualDisk reported: $($_.Exception.Message) - polling for a job anyway"
    }

    # ── 6. Wait, tracking that a rebuild was actually observed ────────────────
    $sawJob = $false
    $suspendedPolls = 0
    $emptyPolls = 0
    $deadline = (Get-Date).AddHours($RepairTimeoutHours)
    $grace = (Get-Date).AddMinutes(3)   # jobs take a moment to register
    while ($true) {
        Start-Sleep -Seconds $PollSeconds
        $jobs = Get-SpaceRepairJob -VirtualDisk $vd
        $active = @($jobs | Where-Object { $_.JobState -match 'Running|Starting|New' })
        $suspended = @($jobs | Where-Object { $_.JobState -match 'Suspended' })

        if ($active.Count -gt 0) {
            $sawJob = $true; $suspendedPolls = 0; $emptyPolls = 0
            $pct = [int]($active[0].PercentComplete)
            Write-State -Stage "repairing" -Message "Rebuilding parity - $pct%" -Percent (10 + [int]($pct * 0.8))
        } elseif ($suspended.Count -gt 0) {
            # Do NOT abort on the first sighting: this pool can carry a stale
            # suspended job from before the new disk supplied the free space,
            # and Storage Spaces needs a little while to pick it back up.
            $emptyPolls = 0; $suspendedPolls++
            if ($suspendedPolls -ge $SuspendedTolerancePolls) {
                Fail ("Parity rebuild stayed SUSPENDED for " +
                      "$([int]($SuspendedTolerancePolls * $PollSeconds / 60)) min (usually not enough free pool " +
                      "space). Old disk NOT removed - safe to re-run this script once resolved.")
            }
            Write-State -Stage "repairing" -Message "Rebuild job suspended - waiting for it to resume ($suspendedPolls/$SuspendedTolerancePolls)"
        } elseif (-not $sawJob -and (Get-Date) -lt $grace) {
            Write-State -Stage "repairing" -Message "Waiting for the rebuild job to register..."
        } else {
            # Parity repairs run in phases with gaps, and the provider can blip.
            # Require several consecutive empty polls before calling it done.
            $suspendedPolls = 0; $emptyPolls++
            if ($emptyPolls -ge $EmptyPollsToFinish) { break }
            Write-State -Stage "repairing" -Message "No active rebuild job ($emptyPolls/$EmptyPollsToFinish) - confirming it has finished"
        }
        if ((Get-Date) -gt $deadline) {
            Fail "Rebuild did not finish within $RepairTimeoutHours h. Old disk NOT removed - safe to re-run."
        }
    }

    # No evidence anything was rebuilt on a space that started degraded.
    if (-not $sawJob -and ($initialHealth -ne 'Healthy' -or -not $repairStarted)) {
        Fail "No rebuild job was ever observed (space started '$initialHealth'). Old disk NOT removed."
    }

    # ── 7. Verify - fresh read, strict, invariants re-asserted ────────────────
    Write-State -Stage "verifying" -Message "Verifying the space is healthy" -Percent 92
    $pool = Get-StoragePool -FriendlyName $PoolName -ErrorAction Stop
    if (@($pool).Count -ne 1) { Fail "Pool '$PoolName' is no longer unique - not removing anything." }
    $vds = @($pool | Get-VirtualDisk -ErrorAction Stop)
    if ($vds.Count -ne 1) { Fail "Pool '$PoolName' no longer has exactly one space - not removing anything." }
    $vd = $vds[0]
    $ops = @($vd.OperationalStatus | ForEach-Object { "$_" })
    if ("$($vd.HealthStatus)" -ne 'Healthy' -or $ops.Count -ne 1 -or $ops[0] -ne 'OK') {
        Fail ("After rebuild the space is $($vd.HealthStatus) / $($ops -join ',') (pool is " +
              "$($pool.HealthStatus) / $($pool.OperationalStatus -join ',')) - refusing to remove the old disk. " +
              "Safe to re-run once resolved.")
    }

    # ── 8. Re-resolve the target and remove it ────────────────────────────────
    # $old was read possibly hours ago: re-fetch by UniqueId and re-assert it is
    # still the retired/missing one before the irreversible command.
    $oldNow = @($pool | Get-PhysicalDisk -ErrorAction Stop | Where-Object { "$($_.UniqueId)" -eq $oldId })
    if ($oldNow.Count -ne 1) { Fail "The old disk is no longer uniquely identifiable - not removing anything." }
    if (-not (Test-DiskGone $oldNow[0])) { Fail "Target disk is no longer retired/missing - refusing to remove it." }
    Write-State -Stage "removing" -Message "Rebuild verified healthy - removing the old disk entry" -Percent 95
    Remove-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $oldNow[0] -Confirm:$false -ErrorAction Stop

    Write-State -Stage "complete" -Message "Done: new drive added, parity rebuilt, old disk removed from the pool." -Percent 100 -Done $true
    exit 0
}
catch {
    Fail "Unexpected error: $($_.Exception.Message)"
}
