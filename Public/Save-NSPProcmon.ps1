function Save-NSPProcmon {
    <#
    .SYNOPSIS
        Downloads Process Monitor from Sysinternals Live (live.sysinternals.com) and keeps it only if
        it carries a valid Microsoft Authenticode signature. Returns the saved path.

    .DESCRIPTION
        The file is downloaded under a temporary name, its signature checked, then renamed into place;
        a file that fails the check is deleted and the function throws. The default folder is the MDE
        work folder (%ProgramData%\NSP\Toolkit\MDE\Tools, Administrators and SYSTEM only) when
        NSP.Toolkit is loaded, otherwise %ProgramData%\NSP\Tools.

    .PARAMETER Destination
        Folder to save into.

    .PARAMETER Uri
        Download address. Defaults to Procmon64.exe (Procmon.exe on 32-bit Windows).

    .EXAMPLE
        Save-NSPProcmon

    .EXAMPLE
        Save-NSPProcmon -Destination 'D:\Tools' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [string]$Destination = (Get-NSPProcmonToolFolder),
        [string]$Uri = $(if ([Environment]::Is64BitOperatingSystem) { 'https://live.sysinternals.com/Procmon64.exe' } else { 'https://live.sysinternals.com/Procmon.exe' })
    )

    if ($Uri -notmatch '^https://') { throw 'Save-NSPProcmon only downloads over HTTPS.' }
    $target = Join-Path $Destination ([IO.Path]::GetFileName(([Uri]$Uri).AbsolutePath))
    if (-not $PSCmdlet.ShouldProcess($target, "Download $Uri")) { return }

    if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
    $temp = "$target.download"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'TLS 1.2 could not be enabled.' }
    try {
        $progress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'   # the 5.1 progress bar slows the download badly
        try { Invoke-WebRequest -Uri $Uri -OutFile $temp -UseBasicParsing -ErrorAction Stop } finally { $ProgressPreference = $progress }
        if (-not (Test-NSPProcmonSignature -Path $temp)) { throw "The download from $Uri is not validly signed by Microsoft - deleted." }
        Move-Item -LiteralPath $temp -Destination $target -Force
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
    return $target
}
