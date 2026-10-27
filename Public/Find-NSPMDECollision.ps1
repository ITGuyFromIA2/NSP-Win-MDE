function Find-NSPMDECollision {
    <#
    .SYNOPSIS
        Finds every SHARING VIOLATION in a ProcMon capture and names the process that held the file
        open at that moment - so the evidence says whether the EDR sensor (MsSense.exe), the
        antivirus engine (MsMpEng.exe) or something else caused it.

    .DESCRIPTION
        The proven signature: the app writes a file, closes it and reopens it exclusively
        (ShareMode: None) a fraction of a millisecond later; MsSense.exe opened the just-written
        file to inspect it and still holds its handle, so the reopen fails with
        STATUS_SHARING_VIOLATION. An antivirus exclusion does not stop the sensor - that needs a
        Defender for Endpoint EDR (Sense) exclusion.

        Two passes: the first finds the paths that had a violation, the second walks only those in
        capture order (a busy minute is hundreds of thousands of opens, almost none relevant).
        Every successful CreateFile opens a handle for that process and path, and the process's
        next CloseFile on the path closes the oldest one (ProcMon's CSV has no handle values, so
        overlapping opens by one process pair up in order). At each violation the handles other
        processes hold on the same path are the holders; their close time is filled in as the walk
        continues.

        HolderKind is the most specific holder seen: EDR (MsSense.exe or another Sense*.exe),
        then AV (MsMpEng.exe, MpDefenderCoreService.exe, NisSrv.exe), then Other. NotSeen means no
        other process opened the file inside the capture - its handle predates the capture.

        ProcessKind classifies the process that was REFUSED the same way. Defender is often the one
        refused - it tries to read a file the app holds exclusively - which is harmless to the app
        and is not evidence; the evidence summary counts those separately.

    .PARAMETER InputObject
        Events from ConvertFrom-NSPProcmonLog (pipeline), in capture order.

    .EXAMPLE
        ConvertFrom-NSPProcmonLog -Path .\capture.csv | Find-NSPMDECollision | Format-Table Time, ProcessName, HolderKind, Path

    .EXAMPLE
        $c = $events | Find-NSPMDECollision; @($c | Where-Object { $_.ProcessKind -eq 'Other' -and $_.HolderKind -eq 'EDR' }).Count
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][Alias('Event')][AllowNull()][object[]]$InputObject)

    begin {
        $all = New-Object Collections.Generic.List[object]
        $violated = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $kindOf = {
            param([string]$Name)
            if ($Name -match '^(MsSense|Sense[A-Za-z]*)\.exe$') { 'EDR' }
            elseif ($Name -match '^(MsMpEng|MpDefenderCoreService|NisSrv)\.exe$') { 'AV' }
            else { 'Other' }
        }
    }
    process {
        foreach ($e in $InputObject) {
            if (-not $e -or -not $e.Path) { continue }
            $all.Add($e)
            if ($e.Result -eq 'SHARING VIOLATION') { $null = $violated.Add([string]$e.Path) }
        }
    }
    end {
        if (-not $violated.Count) { return }
        $open = @{}       # "pid|path" -> handles still open, oldest first
        $byPath = @{}     # path -> every handle still open on it
        $collisions = New-Object Collections.Generic.List[object]

        foreach ($e in $all) {
            if (-not $violated.Contains([string]$e.Path)) { continue }
            $pathKey = ([string]$e.Path).ToUpperInvariant()
            $key = "$($e.PID)|$pathKey"

            if ($e.Operation -eq 'CreateFile' -and $e.Result -eq 'SUCCESS') {
                $handle = [pscustomobject][ordered]@{
                    ProcessName = [string]$e.ProcessName
                    PID         = [string]$e.PID
                    Kind        = & $kindOf ([string]$e.ProcessName)
                    Opened      = [string]$e.Time
                    Closed      = $null
                    HeldMs      = $null
                    ShareMode   = Get-NSPProcmonDetailField -Detail $e.Detail -Name 'ShareMode'
                    OpenedAt    = $e.TimeOfDay
                }
                if (-not $open.ContainsKey($key)) { $open[$key] = New-Object Collections.Generic.List[object] }
                $open[$key].Add($handle)
                if (-not $byPath.ContainsKey($pathKey)) { $byPath[$pathKey] = New-Object Collections.Generic.List[object] }
                $byPath[$pathKey].Add($handle)
            } elseif ($e.Operation -eq 'CloseFile') {
                if ($open.ContainsKey($key) -and $open[$key].Count) {
                    $handle = $open[$key][0]
                    $open[$key].RemoveAt(0)
                    $null = $byPath[$pathKey].Remove($handle)
                    $handle.Closed = [string]$e.Time
                    if ($handle.OpenedAt -is [TimeSpan] -and $e.TimeOfDay -is [TimeSpan]) { $handle.HeldMs = [Math]::Round(($e.TimeOfDay - $handle.OpenedAt).TotalMilliseconds, 4) }
                }
            } elseif ($e.Result -eq 'SHARING VIOLATION') {
                $holders = @(if ($byPath.ContainsKey($pathKey)) { $byPath[$pathKey] | Where-Object { $_.PID -ne [string]$e.PID } })
                $kinds = @($holders | ForEach-Object Kind)
                $holderKind = if ($kinds -contains 'EDR') { 'EDR' } elseif ($kinds -contains 'AV') { 'AV' } elseif ($kinds) { 'Other' } else { 'NotSeen' }
                $collisions.Add([pscustomobject][ordered]@{
                        PSTypeName    = 'NSP.MDE.Collision'
                        Sequence      = $e.Sequence
                        Time          = [string]$e.Time
                        ProcessName   = [string]$e.ProcessName
                        PID           = [string]$e.PID
                        ProcessKind   = & $kindOf ([string]$e.ProcessName)
                        Operation     = [string]$e.Operation
                        Path          = [string]$e.Path
                        DesiredAccess = Get-NSPProcmonDetailField -Detail $e.Detail -Name 'Desired Access'
                        ShareMode     = Get-NSPProcmonDetailField -Detail $e.Detail -Name 'ShareMode'
                        HolderKind    = $holderKind
                        Holders       = $holders
                    })
            }
        }

        # Holders were captured by reference, so their close times are final now. Drop the
        # internal TimeSpan before handing them out.
        foreach ($c in $collisions) {
            $c.Holders = @($c.Holders | Select-Object ProcessName, PID, Kind, Opened, Closed, HeldMs, ShareMode)
            $c
        }
    }
}
