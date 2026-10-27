function New-NSPProcmonFilter {
    <#
    .SYNOPSIS
        Writes a Process Monitor filter file (.pmc) for the sharing-violation proof - natively, no
        Python or ProcMon needed. Returns the file.

    .DESCRIPTION
        ProcMon OR's include rules within one column and requires a match in EVERY column that has
        includes. So "Result is SHARING VIOLATION" and a process-name include must never share a
        file - together they would hide the sensor's own (successful) open. The kinds keep them
        apart:

          Violations  Result is SHARING VIOLATION. The primary proof: any process.
          Activity    Operation is CreateFile/CloseFile, and Path contains one of -Path (the data
                      folder, e.g. '\Clients\'). Shows the handle overlap on the contested files.
          Processes   Process Name is one of -ProcessName (MsSense.exe and MsMpEng.exe are always
                      added), and Operation is CreateFile/CloseFile. Narrow app-plus-Defender view.
          FileOpens   Operation is CreateFile/CloseFile, nothing else. What the analysis exports.
          Custom      -Rule as given.

        The filter only changes what ProcMon shows: the capture keeps every event.

    .PARAMETER Kind
        Which filter to write (see the description).

    .PARAMETER OutputPath
        The .pmc file to write (replaced if it exists).

    .PARAMETER Path
        Path fragments for Activity (matched with "contains").

    .PARAMETER ProcessName
        Executable names for Processes.

    .PARAMETER Rule
        For Custom: objects with Column (ProcessName, PID, Operation, Result, Detail, ImagePath,
        Path, Duration), Relation (Is, IsNot, LessThan, MoreThan, BeginsWith, EndsWith, Contains,
        Excludes), Value and Action (Include or Exclude).

    .EXAMPLE
        New-NSPProcmonFilter -Kind Violations -OutputPath C:\Temp\Violations.pmc

    .EXAMPLE
        New-NSPProcmonFilter -Kind Processes -ProcessName 'pvxwin64.exe' -OutputPath C:\Temp\AppAndEdr.pmc
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([IO.FileInfo])]
    param(
        [Parameter(Mandatory)][ValidateSet('Violations', 'Activity', 'Processes', 'FileOpens', 'Custom')][string]$Kind,
        [Parameter(Mandatory)][string]$OutputPath,
        [string[]]$Path = @(),
        [string[]]$ProcessName = @(),
        [object[]]$Rule = @()
    )

    $new = { param($Column, $Relation, $Value) [pscustomobject]@{ Column = $Column; Relation = $Relation; Value = $Value; Action = 'Include' } }
    $opens = @((& $new 'Operation' 'Is' 'CreateFile'), (& $new 'Operation' 'Is' 'CloseFile'))
    $rules = switch ($Kind) {
        'Violations' { , @(& $new 'Result' 'Is' 'SHARING VIOLATION') }
        'Activity' {
            $fragments = @($Path | Where-Object { $_ } | Select-Object -Unique)
            if (-not $fragments) { throw 'Activity needs at least one -Path fragment (e.g. ''\Clients\'').' }
            , ($opens + @($fragments | ForEach-Object { & $new 'Path' 'Contains' $_ }))
        }
        'Processes' {
            $names = @(@($ProcessName) + 'MsSense.exe', 'MsMpEng.exe' | Where-Object { $_ } | Select-Object -Unique)
            , (@($names | ForEach-Object { & $new 'ProcessName' 'Is' $_ }) + $opens)
        }
        'FileOpens' { , $opens }
        'Custom' {
            if (-not $Rule) { throw 'Custom needs -Rule.' }
            , @($Rule | ForEach-Object { [pscustomobject]@{ Column = $_.Column; Relation = $_.Relation; Value = $_.Value; Action = $(if ($_.Action) { $_.Action } else { 'Include' }) } })
        }
    }

    $bytes = ConvertTo-NSPProcmonConfigBytes -Rule $rules
    if (-not $PSCmdlet.ShouldProcess($OutputPath, "Write ProcMon filter ($Kind, $(@($rules).Count) rules)")) { return }
    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllBytes($OutputPath, $bytes)
    Get-Item -LiteralPath $OutputPath
}
