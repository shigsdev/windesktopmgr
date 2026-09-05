<#
.SYNOPSIS
    Replace a retired/failed Storage Spaces disk: add the new drive, rebuild
    parity, then (only on a verified-healthy rebuild) drop the old disk.

.DESCRIPTION
    Drives the post-swap sequence the Storage tab's "Replace & repair pool"
    button kicks off. Runs ELEVATED (Storage Spaces cmdlets require admin) and
    writes structured JSON progress to -StateFile so the app can poll it.

    Order matters and is enforced:
        1. validate pool / virtual disk / exactly one new poolable disk
        2. Add-PhysicalDisk        (new drive joins the pool)
        3. Repair-VirtualDisk      (parity rebuild — can run for hours)
        4. poll Get-StorageJob until the rebuild finishes
        5. VERIFY the virtual disk is Healthy + OK
        6. Remove-PhysicalDisk     (the old retired/lost disk)

    Step 6 is HARD-GATED on step 5. With PhysicalDiskRedundancy = 1, removing
    the old disk while the rebuild is incomplete or unhealthy can lose the
    volume, so any failure/timeout/suspension stops before the removal and
    leaves the pool in a recoverable state.

.NOTES
    -Preview writes the plan and exits without changing anything.
#>
[CmdletBinding()]
param(
    [string]$PoolName = "Storage pool",
    [string]$VirtualDiskName = "Storage space",
    [string]$RetiredSerial = "",
    [string]$StateFile = "",
    [int]$RepairTimeoutHours = 12,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
$script:State = [ordered]@{
    stage      = "starting"
    ok         = $true
    done       = $false
    percent    = 0
    message    = ""
    error      = ""
    plan       = $null
    started    = (Get-Date).ToString("o")
    updated    = (Get-Date).ToString("o")
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
            $tmp = "$StateFile.tmp"
            ($script:State | ConvertTo-Json -Depth 5) | Set-Content -Path $tmp -Encoding UTF8
            Move-Item -Path $tmp -Destination $StateFile -Force
        } catch { }
    }
    Write-Output "[$($script:State.stage)] $($script:State.message)"
}

function Fail {
    param([string]$Text)
    Write-State -Stage "failed" -Message $Text -Done $true -ErrorText $Text
    exit 1
}

try {
    # ── 1. Validate targets ───────────────────────────────────────────────────
    Write-State -Stage "validating" -Message "Checking pool and virtual disk" -Percent 0

    $pool = Get-StoragePool -FriendlyName $PoolName -ErrorAction SilentlyContinue
    if (-not $pool) { Fail "Storage pool '$PoolName' not found." }

    $vd = Get-VirtualDisk -FriendlyName $VirtualDiskName -ErrorAction SilentlyContinue
    if (-not $vd) { Fail "Virtual disk '$VirtualDiskName' not found." }

    # The disk to remove: prefer an exact serial match, else the single pool
    # member that is Retired or has lost communication (i.e. physically pulled).
    $members = @($pool | Get-PhysicalDisk -ErrorAction SilentlyContinue)
    $normalize = { param($s) ($s -replace '[^A-Za-z0-9]', '').ToLower() }
    $old = $null
    if ($RetiredSerial) {
        $want = & $normalize $RetiredSerial
        $old = @($members | Where-Object { (& $normalize $_.SerialNumber) -eq $want })
    }
    if (-not $old -or $old.Count -eq 0) {
        $old = @($members | Where-Object {
            $_.Usage -eq 'Retired' -or ($_.OperationalStatus -join ',') -match 'Lost Communication|Unrecognized|Removed'
        })
    }
    if ($old.Count -eq 0) { Fail "No retired/missing disk found in '$PoolName' — nothing to replace." }
    if ($old.Count -gt 1) { Fail "Ambiguous: $($old.Count) retired/missing disks in '$PoolName'. Resolve manually." }
    $old = $old[0]

    # The new drive: must be exactly one poolable disk.
    $new = @(Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue)
    if ($new.Count -eq 0) { Fail "No new poolable disk detected. Fit the replacement drive first (it must be uninitialised)." }
    if ($new.Count -gt 1) { Fail "Ambiguous: $($new.Count) poolable disks detected. Leave only the replacement unpooled." }
    $new = $new[0]

    $script:State.plan = [ordered]@{
        pool         = $PoolName
        virtual_disk = $VirtualDiskName
        add_model    = "$($new.FriendlyName)"
        add_serial   = "$($new.SerialNumber)".Trim()
        add_size_gb  = [math]::Round($new.Size / 1GB)
        remove_model = "$($old.FriendlyName)"
        remove_serial= "$($old.SerialNumber)".Trim()
        remove_usage = "$($old.Usage)"
        resiliency   = "$($vd.ResiliencySettingName)"
    }

    if ($Preview) {
        Write-State -Stage "preview" -Message "Plan only — nothing changed." -Percent 0 -Done $true
        exit 0
    }

    # ── 2. Add the new disk ───────────────────────────────────────────────────
    Write-State -Stage "adding" -Message "Adding $($new.FriendlyName) to '$PoolName'" -Percent 5
    Add-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $new -ErrorAction Stop

    # ── 3. Start the parity rebuild ───────────────────────────────────────────
    Write-State -Stage "repairing" -Message "Starting parity rebuild (this can take hours)" -Percent 10
    try {
        Repair-VirtualDisk -FriendlyName $VirtualDiskName -AsJob -ErrorAction Stop | Out-Null
    } catch {
        # Some builds run Repair-VirtualDisk synchronously / a suspended job may
        # simply resume once space exists. Fall through to job polling either way.
        Write-State -Stage "repairing" -Message "Repair kicked off ($($_.Exception.Message)); polling jobs"
    }

    # ── 4. Poll until the rebuild finishes ────────────────────────────────────
    $deadline = (Get-Date).AddHours($RepairTimeoutHours)
    while ($true) {
        Start-Sleep -Seconds 20
        $jobs = @(Get-StorageJob -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Repair|Regenerat|Rebuild' })
        $active = @($jobs | Where-Object { $_.JobState -match 'Running|Starting|New' })
        $suspended = @($jobs | Where-Object { $_.JobState -match 'Suspended' })

        if ($active.Count -gt 0) {
            $pct = [int]($active[0].PercentComplete)
            # map rebuild 0-100% onto the 10-90 band of overall progress
            Write-State -Stage "repairing" -Message "Rebuilding parity — $pct%" -Percent (10 + [int]($pct * 0.8))
        } elseif ($suspended.Count -gt 0) {
            Fail "Parity rebuild is SUSPENDED (usually not enough free pool space). Old disk NOT removed."
        } else {
            break  # no repair jobs left
        }
        if ((Get-Date) -gt $deadline) {
            Fail "Rebuild did not finish within $RepairTimeoutHours h. Old disk NOT removed."
        }
    }

    # ── 5. VERIFY before touching the old disk ────────────────────────────────
    Write-State -Stage "verifying" -Message "Verifying the virtual disk is healthy" -Percent 92
    $vd = Get-VirtualDisk -FriendlyName $VirtualDiskName -ErrorAction Stop
    $health = "$($vd.HealthStatus)"
    $oper = ($vd.OperationalStatus -join ',')
    if ($health -ne 'Healthy' -or $oper -notmatch 'OK') {
        Fail "Rebuild finished but '$VirtualDiskName' is $health / $oper — refusing to remove the old disk."
    }

    # ── 6. Remove the old disk (only now) ─────────────────────────────────────
    Write-State -Stage "removing" -Message "Rebuild verified healthy — removing the old disk" -Percent 95
    Remove-PhysicalDisk -StoragePoolFriendlyName $PoolName -PhysicalDisks $old -Confirm:$false -ErrorAction Stop

    Write-State -Stage "complete" -Message "Pool repaired: new drive in, parity rebuilt, old disk removed." -Percent 100 -Done $true
    exit 0
}
catch {
    Fail "Unexpected error: $($_.Exception.Message)"
}
