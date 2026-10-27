function ConvertFrom-NSPProcmonLog {
    <#
    .SYNOPSIS
        Reads a Process Monitor capture as events: a .pml is exported to CSV with ProcMon first
        (opens and closes of the files that had a sharing violation, unless -FilterPath says
        otherwise), a .csv is read as is.

    .DESCRIPTION
        Each event has Sequence (row order), TimeOfDay (a TimeSpan, 100 ns precision), Time (the
        text), ProcessName, PID, Operation, Path, Result and Detail - what Find-NSPMDECollision
        needs. The CSV must have ProcMon's default columns (Time of Day, Process Name, PID,
        Operation, Path, Result, Detail); reset ProcMon's columns if one is missing.

        Exporting runs: Procmon /OpenLog <pml> /LoadConfig <filter> /SaveApplyFilter /SaveAs <csv>,
        twice by default: first the sharing violations (<name>.violations.csv), then CreateFile
        and CloseFile on just the files that had one (<name>.csv) - a capture with no violations
        yields no events. More than 253 such files falls back to every open and close. The CSVs
        are written next to the .pml and reused if already there.

    .PARAMETER Path
        A .pml backing file or a .csv ProcMon export.

    .PARAMETER ProcmonPath
        Process Monitor executable (only for a .pml).

    .PARAMETER FilterPath
        Export once with this filter instead (New-NSPProcmonFilter), e.g. -Kind FileOpens for
        every open and close.

    .PARAMETER Force
        Export again even if the CSV exists.

    .EXAMPLE
        ConvertFrom-NSPProcmonLog -Path C:\Captures\capture.pml -ProcmonPath (Find-NSPProcmon) | Find-NSPMDECollision

    .EXAMPLE
        ConvertFrom-NSPProcmonLog -Path C:\Captures\Logfile.CSV
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ProcmonPath,
        [string]$FilterPath,
        [switch]$Force
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Not found: $Path" }
    $Path = (Resolve-Path -LiteralPath $Path).ProviderPath
    $csv = $Path
    if ([IO.Path]::GetExtension($Path) -ieq '.pml') {
        $csv = [IO.Path]::ChangeExtension($Path, '.csv')
        if ($Force -or -not (Test-Path -LiteralPath $csv)) {
            if (-not $ProcmonPath) { throw 'Exporting a .pml needs -ProcmonPath (Find-NSPProcmon).' }
            if (-not (Test-NSPProcmonSignature -Path $ProcmonPath)) { throw "$ProcmonPath is not validly signed by Microsoft - not running it." }
            $temp = Join-Path ([IO.Path]::GetTempPath()) ("NSP_{0}" -f [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $temp -Force
            try {
                if ($FilterPath) {
                    Export-NSPProcmonCsv -ProcmonPath $ProcmonPath -Path $Path -FilterPath $FilterPath -CsvPath $csv
                } else {
                    # Stage 1: the (few) violations, to learn which files matter. Stage 2: opens and
                    # closes on exactly those files - a busy minute is hundreds of thousands of
                    # opens, and reading them all back costs minutes.
                    $violationsCsv = [IO.Path]::ChangeExtension($Path, '.violations.csv')
                    $violations = (New-NSPProcmonFilter -Kind Violations -OutputPath (Join-Path $temp 'v.pmc') -WhatIf:$false).FullName
                    Export-NSPProcmonCsv -ProcmonPath $ProcmonPath -Path $Path -FilterPath $violations -CsvPath $violationsCsv
                    $paths = @(Import-Csv -LiteralPath $violationsCsv | ForEach-Object Path | Where-Object { $_ } | Sort-Object -Unique)
                    Write-Verbose "$($paths.Count) file(s) had a sharing violation."
                    if (-not $paths) {
                        Copy-Item -LiteralPath $violationsCsv -Destination $csv -Force
                    } else {
                        $kind = 'FileOpens'; $rules = @()
                        if ($paths.Count -le 253) {
                            $kind = 'Custom'
                            $rules = @(
                                [pscustomobject]@{ Column = 'Operation'; Relation = 'Is'; Value = 'CreateFile'; Action = 'Include' }
                                [pscustomobject]@{ Column = 'Operation'; Relation = 'Is'; Value = 'CloseFile'; Action = 'Include' }
                            ) + @($paths | ForEach-Object { [pscustomobject]@{ Column = 'Path'; Relation = 'Is'; Value = $_; Action = 'Include' } })
                        }
                        $opens = (New-NSPProcmonFilter -Kind $kind -Rule $rules -OutputPath (Join-Path $temp 'o.pmc') -WhatIf:$false).FullName
                        Export-NSPProcmonCsv -ProcmonPath $ProcmonPath -Path $Path -FilterPath $opens -CsvPath $csv
                    }
                }
            } finally {
                Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $required = 'Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail'
    $header = @((Get-Content -LiteralPath $csv -TotalCount 1) -split '","' | ForEach-Object { $_.Trim().Trim('"').TrimStart([char]0xFEFF) })
    $missing = @($required | Where-Object { $header -notcontains $_ })
    if ($missing) { throw "$csv is missing ProcMon column(s): $($missing -join ', '). Reset ProcMon's columns (Options > Select Columns) and export again." }

    $sequence = 0
    Import-Csv -LiteralPath $csv | ForEach-Object {
        $sequence++
        [pscustomobject]@{
            PSTypeName  = 'NSP.MDE.ProcmonEvent'
            Sequence    = $sequence
            TimeOfDay   = ConvertFrom-NSPProcmonTimeOfDay $_.'Time of Day'
            Time        = $_.'Time of Day'
            ProcessName = $_.'Process Name'
            PID         = $_.PID
            Operation   = $_.Operation
            Path        = $_.Path
            Result      = $_.Result
            Detail      = $_.Detail
        }
    }
}
