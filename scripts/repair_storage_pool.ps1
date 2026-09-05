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
        add       -> Add-PhysicalDisk (the new drive joins the pool)
        repair    -> Repair-VirtualDisk (parity rebuild; can run for HOURS)
        wait      -> poll Get-StorageJob until the rebuild finishes
        verify    -> the virtual disk must be Healthy and OperationalStatus OK
        remove    -> Remove-PhysicalDisk (the old disk's stale pool entry)

    The removal is HARD-GATED on the verification. With PhysicalDiskRedundancy
    = 1, dropping the old disk while the rebuild is incomplete can lose the
    volume, so any failure / suspension / timeout stops BEFORE the removal and
    leaves the pool recoverable. It also refuses to run at all when anything is
    ambiguous (more than one pool space, more than one retired disk, more than
    one poolable replacement) rather than guessing.

    Requires Administrator: Storage Spaces cmdlets do not work unelevated.

.EXAMPLE
    # Preview only — shows exactly which disk would be added and which removed,
    # changes nothing:
    powershell -ExecutionPolicy Bypass -File .\scripts\repair_storage_pool.ps1 -Preview

.EXAMPLE
    # Do it for real (leave the window open; the rebuild takes hours):
    powershell -ExecutionPolicy Bypass -File .\scripts\repair_storage_pool.ps1

.NOTES
    -StateFile optionally mirrors progress to a JSON file (BOM-free) so you can
    tail it from elsewhere. Console output is the primary progress display.
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
$script:State = [ordered]@{
    stage = "starting"; ok = $true; done = $false; percent = 0
    message = ""; error = ""; plan = $null
    started = (Get-Date).ToString("o"); updated = (Get-Date).ToString("o")
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
            # WriteAllText with a BOM-less UTF8 encoder — Set-Content -Encoding
            # UTF8 on Windows PowerShell 5.1 emits a BOM that breaks JSON readers.
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

# A pool member counts as "gone" when Storage Spaces has retired it or lost it.
function Test-DiskGone {
    param($Disk)
    if ($Disk.Usage -eq 'Retired') { return $true }
    return (($Disk.OperationalStatus -join ',') -match 'Lost Communication|Unrecognized|Removed')
}

function ConvertTo-SerialKey {
    param([string]$Serial)
    return ($Serial -replace '[^A-Za-z0-9]', '').ToLower()
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

    # Scope the virtual disk to THIS pool. Remove-PhysicalDisk drops the disk
    # from the whole pool, so every space on it must be rebuilt and verified —
    # this script only handles the single-space case and refuses otherwise.
    $vds = @($pool | Get-VirtualDisk -ErrorAction SilentlyContinue)
    if ($vds.Count -eq 0) { Fail "Pool '$PoolName' has no virtual disk." }
    if ($vds.Count -gt 1) {
        Fail ("Pool '$PoolName' has $($vds.Count) spaces. Removing a disk affects all of them and this " +
              "script only verifies one — repair manually.")
    }
    $vd = $vds[0]
    $initialHealth = "$($vd.HealthStatus)"

    # ── 2. Pick the disk to remove — only ever a retired/missing member ───────
    $members = @($pool | Get-PhysicalDisk -ErrorAction SilentlyContinue)
    $gone = @($members | Where-Object { Test-DiskGone $_ })
    if ($gone.Count -eq 0) { Fail "No retired or missing disk in '$PoolName' — nothing to replace." }
    # A serial may only NARROW the already-retired set; it can never select a
    # healthy in-use member. Short/blank keys are ignored (they match anything).
    if ($RetiredSerial) {
        $want = ConvertTo-SerialKey $RetiredSerial
        if ($want.Length -ge 4) {
            $bySerial = @($gone | Where-Object { (ConvertTo-SerialKey $_.SerialNumber) -eq $want })
            if ($bySerial.Count -eq 1) { $gone = $bySerial }
        }
    }
    if ($gone.Count -gt 1) { Fail "Ambiguous: $($gone.Count) retired/missing disks in '$PoolName'. Resolve manually." }
    $old = $gone[0]
    $oldId = $old.UniqueId

    # ── 3. Pick the replacement — real internal disk, not smaller ────────────
    $new = @(Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue |
             Where-Object { $_.BusType -notin @('USB', 'SD', 'MMC') })
    if ($new.Count -eq 0) {
        Fail "No suitable new disk found. Fit the replacement (internal, uninitialised/unpooled) and re-run."
    }
    if ($new.Count -gt 1) { Fail "Ambiguous: $($new.Count) poolable disks. Leave only the replacement unpooled." }
    $new = $new[0]
    if ($old.Size -and $new.Size -lt $old.Size) {
        Fail ("Replacement ($([math]::Round($new.Size/1GB)) GB) is smaller than the disk it replaces " +
              "($([math]::Round($old.Size/1GB)) GB).")
    }

    $script:State.plan = [ordered]@{
        pool = $PoolName; space = "$($vd.FriendlyName)"; resiliency = "$($vd.ResiliencySettingName)"
        add_model = "$($new.FriendlyName)"; add_serial = "$($new.SerialNumber)".Trim()
        add_size_gb = [math]::Round($new.Size / 1GB)
        remove_model = "$($old.FriendlyName)"; remove_serial = "$($old.SerialNumber)".Trim()
        remove_usage = "$($old.Usage)"
    }
    Write-Host ""
    Write-Host "  Pool    : $PoolName / $($vd.FriendlyName) ($($vd.ResiliencySettingName))"
    Write-Host "  ADD     : $($new.FriendlyName)  serial $($new.SerialNumber)  $([math]::Round($new.Size/1GB)) GB"
    Write-Host "  REMOVE  : $($old.FriendlyName)  serial $($old.SerialNumber)  ($($old.Usage))"
    Write-Host ""

    if ($Preview) {
        Write-State -Stage "preview" -Message "Preview only — nothing was changed." -Done $true
        exit 0
    }

    # ── 4. Add the replacement ────────────────────────────────────────────────
    Write-State -Stage "adding" -Message "Adding $($new.FriendlyName) to '$PoolName'" -Percent 5
    Add-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $new -ErrorAction Stop

    # ── 5. Start the parity rebuild ───────────────────────────────────────────
    Write-State -Stage "repairing" -Message "Starting parity rebuild — this can take hours" -Percent 10
    $repairStarted = $true
    try {
        Repair-VirtualDisk -FriendlyName $vd.FriendlyName -AsJob -ErrorAction Stop | Out-Null
    } catch {
        $repairStarted = $false
        Write-State -Stage "repairing" -Message "Repair-VirtualDisk reported: $($_.Exception.Message) — polling for a job anyway"
    }

    # ── 6. Wait for it, tracking that a rebuild was actually observed ─────────
    $sawJob = $false
    $deadline = (Get-Date).AddHours($RepairTimeoutHours)
    $grace = (Get-Date).AddMinutes(3)   # jobs can take a moment to register
    while ($true) {
        Start-Sleep -Seconds 20
        $jobs = @(Get-StorageJob -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Repair|Regenerat|Rebuild' })
        $active = @($jobs | Where-Object { $_.JobState -match 'Running|Starting|New' })
        $suspended = @($jobs | Where-Object { $_.JobState -match 'Suspended' })

        if ($active.Count -gt 0) {
            $sawJob = $true
            $pct = [int]($active[0].PercentComplete)
            Write-State -Stage "repairing" -Message "Rebuilding parity — $pct%" -Percent (10 + [int]($pct * 0.8))
        } elseif ($suspended.Count -gt 0) {
            Fail "Parity rebuild is SUSPENDED (usually not enough free pool space). Old disk NOT removed."
        } elseif (-not $sawJob -and (Get-Date) -lt $grace) {
            Write-State -Stage "repairing" -Message "Waiting for the rebuild job to register..."
        } else {
            break
        }
        if ((Get-Date) -gt $deadline) { Fail "Rebuild did not finish within $RepairTimeoutHours h. Old disk NOT removed." }
    }

    # If the space was degraded but we never saw a rebuild run, we have no
    # evidence anything was rebuilt — refuse rather than trust a health read.
    if (-not $sawJob -and ($initialHealth -ne 'Healthy' -or -not $repairStarted)) {
        Fail "No rebuild job was ever observed (space started '$initialHealth'). Old disk NOT removed."
    }

    # ── 7. Verify — fresh read, strict ────────────────────────────────────────
    Write-State -Stage "verifying" -Message "Verifying the space is healthy" -Percent 92
    $pool = Get-StoragePool -FriendlyName $PoolName -ErrorAction Stop
    $vd = @($pool | Get-VirtualDisk -ErrorAction Stop)[0]
    $ops = @($vd.OperationalStatus | ForEach-Object { "$_" })
    if ("$($vd.HealthStatus)" -ne 'Healthy' -or $ops.Count -ne 1 -or $ops[0] -ne 'OK') {
        Fail "After rebuild the space is $($vd.HealthStatus) / $($ops -join ',') — refusing to remove the old disk."
    }

    # ── 8. Re-resolve the target and remove it ────────────────────────────────
    # $old was read hours ago; re-fetch by UniqueId and re-assert it is still
    # the retired/missing one before running the irreversible command.
    $oldNow = @($pool | Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.UniqueId -eq $oldId })
    if ($oldNow.Count -ne 1) { Fail "The old disk is no longer uniquely identifiable — not removing anything." }
    if (-not (Test-DiskGone $oldNow[0])) {
        Fail "Target disk is no longer retired/missing — refusing to remove it."
    }
    Write-State -Stage "removing" -Message "Rebuild verified healthy — removing the old disk entry" -Percent 95
    Remove-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $oldNow[0] -Confirm:$false -ErrorAction Stop

    Write-State -Stage "complete" -Message "Done: new drive added, parity rebuilt, old disk removed from the pool." -Percent 100 -Done $true
    exit 0
}
catch {
    Fail "Unexpected error: $($_.Exception.Message)"
}
