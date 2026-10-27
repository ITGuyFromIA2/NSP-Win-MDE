function Export-NSPMDEResponse {
    <#
    .SYNOPSIS
        Writes the hand-back JSON (<Company>_MDE_Response.json): this machine's Defender for Endpoint
        facts, the candidate apps, the capture, the collision evidence with its verdict, and a
        suggested exclusion - for the tech to fill in the EDR exclusion request. Returns the file.

    .DESCRIPTION
        Written as an NSP.Toolkit Response hand-off (shared header, SHA-256 of the payload) when
        NSP.Toolkit is loaded, plain JSON otherwise. The file is read back and checked before it is
        returned; a file that fails is deleted and the function throws. The ProcMon files are not
        embedded - they stay next to the capture, identified by name, size and SHA-256.

    .PARAMETER Company
        Client the evidence belongs to.

    .PARAMETER OutputDirectory
        Folder to write to (the MDE Responses work folder by default).

    .PARAMETER ApplicationName
        The line-of-business app as the client knows it (e.g. "Sage 100").

    .PARAMETER Status
        Get-NSPMDEStatus output (read now when omitted).

    .PARAMETER Candidate
        Get-NSPMDECandidateApp output.

    .PARAMETER Capture
        The capture object (Start-/Stop-NSPProcmonCapture).

    .PARAMETER Collision
        Find-NSPMDECollision output.

    .PARAMETER TechNotes
        Free text for the request.

    .PARAMETER MaxCollisions
        How many collisions to include in full (all are counted).

    .EXAMPLE
        Export-NSPMDEResponse -Company 'Example Co' -ApplicationName 'Sage 100' -Collision $collisions -Capture $capture

    .EXAMPLE
        Export-NSPMDEResponse -Company 'Example Co' -OutputDirectory C:\Temp -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([IO.FileInfo])]
    param(
        [Parameter(Mandatory)][string]$Company,
        [string]$OutputDirectory,
        [string]$ApplicationName,
        $Status,
        [object[]]$Candidate,
        $Capture,
        [object[]]$Collision,
        [string]$TechNotes,
        [ValidateRange(1, 1000)][int]$MaxCollisions = 25
    )

    $useHandoff = [bool](Get-Command New-NSPHandoff -ErrorAction SilentlyContinue)
    if (-not $OutputDirectory) {
        $OutputDirectory = if (Get-Command Get-NSPToolWorkPath -ErrorAction SilentlyContinue) { Get-NSPToolWorkPath -Tool MDE -Kind Responses } else { Join-Path $env:ProgramData 'NSP\MDE\Responses' }
    }
    if (-not $Status) { $Status = Get-NSPMDEStatus }
    $version = [string]$ExecutionContext.SessionState.Module.Version

    $sha = ''; $bytes = $null; $csvName = ''
    if ($Capture -and $Capture.BackingFile -and (Test-Path -LiteralPath $Capture.BackingFile -PathType Leaf)) {
        $sha = Get-NSPFileSha256 -Path $Capture.BackingFile
        $bytes = (Get-Item -LiteralPath $Capture.BackingFile).Length
        $csv = [IO.Path]::ChangeExtension($Capture.BackingFile, '.csv')
        if (Test-Path -LiteralPath $csv) { $csvName = Split-Path -Leaf $csv }
    }

    $payload = New-NSPMDEResponsePayload -Company $Company -ApplicationName $ApplicationName -Status $Status -Candidate $Candidate `
        -Capture $Capture -Collision $Collision -TechNotes $TechNotes -MaxCollisions $MaxCollisions -ToolVersion $version `
        -BackingFileSha256 $sha -BackingFileBytes $bytes -CsvFile $csvName

    $stem = ($Company -replace '[^A-Za-z0-9_-]', '')
    $target = Join-Path $OutputDirectory "${stem}_MDE_Response.json"
    if (-not $PSCmdlet.ShouldProcess($target, 'Write the MDE hand-back')) { return }
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    if ($useHandoff) {
        $handoff = New-NSPHandoff -Kind Response -Tool MDE -Company $Company -Payload $payload -PayloadSchema $payload.SchemaVersion `
            -ToolVersion $version -GeneratedBy "NSP.Win.MDE $version" -ComputerName $payload.ComputerName -Domain $payload.Domain
        $path = (Export-NSPHandoff -Handoff $handoff -Directory $OutputDirectory -Confirm:$false).FullName
    } else {
        $path = $target
        [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $payload -Depth 20), (New-Object Text.UTF8Encoding($false)))
    }

    $problem = $null
    try {
        $check = if ($useHandoff) { (Import-NSPHandoff -Path $path -Tool MDE -Kind Response).Payload } else { ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path)) }
        if ($check.SchemaVersion -ne $script:NSPMDEResponseSchema) { $problem = 'the schema version did not survive' }
        elseif ([int]$check.Evidence.Violations -ne [int]$payload.Evidence.Violations) { $problem = 'the evidence counts did not survive' }
    } catch { $problem = "it could not be read back: $($_.Exception.Message)" }
    if ($problem) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw "Hand-back check failed - $problem. The file was deleted."
    }
    Get-Item -LiteralPath $path
}
