function Stop-NSPProcmonCapture {
    <#
    .SYNOPSIS
        Stops a running Process Monitor capture (Procmon /Terminate) and waits until the backing file
        is complete. Returns the capture with Ended set.

    .DESCRIPTION
        Waits for every ProcMon process to exit and the backing file to be released, up to
        -TimeoutSeconds. A capture started with -RuntimeSeconds may already have stopped; that's
        fine.

        Then measures how many seconds the backing file really covers (CoveredSeconds) and
        warns when that is well short of the time it ran (Incomplete = $true): ProcMon
        occasionally writes a file that holds only its first second, which would otherwise read
        as "no sharing violations". Capture again when that happens.

    .PARAMETER Capture
        The object from Start-NSPProcmonCapture.

    .PARAMETER ProcmonPath
        Process Monitor executable, when there is no capture object (stops whatever is running).

    .PARAMETER TimeoutSeconds
        How long to wait for ProcMon to finish writing.

    .EXAMPLE
        $c = $c | Stop-NSPProcmonCapture

    .EXAMPLE
        Stop-NSPProcmonCapture -ProcmonPath (Find-NSPProcmon)
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Capture')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Capture')][object]$Capture,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$ProcmonPath,
        [int]$TimeoutSeconds = 120
    )
    process {
        $exe = if ($Capture) { $Capture.ProcmonPath } else { $ProcmonPath }
        if (-not $PSCmdlet.ShouldProcess($exe, 'Stop the ProcMon capture')) { return }

        $running = { @(Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue) }
        if ((& $running).Count) {
            if (-not (Test-NSPProcmonSignature -Path $exe)) { throw "$exe is not validly signed by Microsoft - not running it." }
            $null = Invoke-NSPProcmonExe -FilePath $exe -ArgumentList '/Terminate' -Wait
        }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((& $running).Count -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if ((& $running).Count) { Write-Warning "ProcMon is still running after $TimeoutSeconds seconds." }

        if ($Capture -and $Capture.BackingFile) {
            # ProcMon may still be flushing for a moment after it exits.
            while ((Get-Date) -lt $deadline) {
                if (-not (Test-Path -LiteralPath $Capture.BackingFile)) { Start-Sleep -Milliseconds 500; continue }
                try { [IO.File]::Open($Capture.BackingFile, 'Open', 'Read', 'None').Dispose(); break } catch { Start-Sleep -Milliseconds 500 }
            }
            $Capture.Ended = Get-Date
            if (-not (Test-Path -LiteralPath $Capture.BackingFile)) {
                Write-Warning "No backing file at $($Capture.BackingFile) - ProcMon may not have captured (was it elevated?)."
                return $Capture
            }
            $covered = Get-NSPProcmonCoverage -ProcmonPath $exe -Path $Capture.BackingFile
            $ran = if ($Capture.Started) { ($Capture.Ended - [datetime]$Capture.Started).TotalSeconds } else { $null }
            $incomplete = ($null -ne $covered -and $null -ne $ran -and $ran - $covered -gt 10 -and $covered -lt $ran * 0.5)
            foreach ($p in @{ CoveredSeconds = $covered; Incomplete = $incomplete }.GetEnumerator()) {
                $Capture | Add-Member -NotePropertyName $p.Key -NotePropertyValue $p.Value -Force
            }
            if ($incomplete) { Write-Warning ("The capture covers only {0:N0} of the {1:N0} seconds ProcMon ran - ProcMon wrote an incomplete file. Capture again." -f $covered, $ran) }
            return $Capture
        }
    }
}
