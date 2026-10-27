function Get-NSPMDECandidateApp {
    <#
    .SYNOPSIS
        Collapses crash events (Get-NSPMDECrashEvent) into one row per executable: how often it
        failed, where it lives, on which computers, first and last seen, exception codes.

    .PARAMETER InputObject
        Records from Get-NSPMDECrashEvent (pipeline).

    .PARAMETER ProcessName
        Keep only these executables (e.g. the app the client complains about). Case-insensitive.

    .EXAMPLE
        Get-NSPMDECrashEvent -Days 30 | Get-NSPMDECandidateApp

    .EXAMPLE
        Get-NSPMDECrashEvent | Get-NSPMDECandidateApp -ProcessName 'pvxwin64.exe'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][Alias('Event')][AllowNull()][object[]]$InputObject,
        [string[]]$ProcessName = @()
    )
    begin { $all = New-Object Collections.Generic.List[object] }
    process { foreach ($e in $InputObject) { if ($e) { $all.Add($e) } } }
    end {
        # .ToArray(), not @($all): pwsh 7.6 throws "Argument types do not match" on @() of a List
        # made with New-Object.
        $kept = if ($ProcessName) { @($all | Where-Object { $ProcessName -contains $_.ExeName }) } else { $all.ToArray() }
        $kept | Group-Object ExeName | ForEach-Object {
            $g = $_.Group
            [pscustomobject][ordered]@{
                PSTypeName     = 'NSP.MDE.CandidateApp'
                ExeName        = $_.Name
                Hits           = $_.Count
                ExePaths       = @($g.ExePath | Where-Object { $_ } | Sort-Object -Unique)
                Computers      = @($g.Computer | Where-Object { $_ } | Sort-Object -Unique)
                FirstSeen      = ($g.TimeCreated | Measure-Object -Minimum).Minimum
                LastSeen       = ($g.TimeCreated | Measure-Object -Maximum).Maximum
                ExceptionCodes = @($g.ExceptionCode | Where-Object { $_ } | Sort-Object -Unique)
                EventIds       = @($g.EventId | Sort-Object -Unique)
            }
        } | Sort-Object Hits -Descending
    }
}
