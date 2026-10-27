function Find-NSPProcmon {
    <#
    .SYNOPSIS
        Finds a Microsoft-signed Process Monitor: the given file or folder, then NSP_PROCMON, then the
        NSP tool folders, Sysinternals folders and PATH. Returns its full path, or nothing.

    .DESCRIPTION
        Procmon64.exe is preferred over Procmon.exe on 64-bit Windows. A copy without a valid
        Microsoft Authenticode signature is skipped with a warning - the troubleshooter runs ProcMon
        elevated, and some of these folders can be written by ordinary users. Save-NSPProcmon
        downloads it when nothing is found.

    .PARAMETER Path
        A ProcMon executable, or a folder holding one.

    .EXAMPLE
        Find-NSPProcmon

    .EXAMPLE
        Find-NSPProcmon -Path 'D:\Sysinternals'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Path)

    $names = if ([Environment]::Is64BitOperatingSystem) { 'Procmon64.exe', 'Procmon.exe' } else { , 'Procmon.exe' }
    $folders = @(
        $Path, $env:NSP_PROCMON, (Get-NSPProcmonToolFolder), (Join-Path $env:ProgramData 'NSP\Tools'),
        (Join-Path $env:ProgramFiles 'Sysinternals'), $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Sysinternals' }),
        (Join-Path $env:SystemDrive 'Tools\Sysinternals')
    ) | Where-Object { $_ } | Select-Object -Unique

    $candidates = foreach ($candidate in $folders) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { (Resolve-Path -LiteralPath $candidate).ProviderPath; continue }
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            foreach ($name in $names) {
                $file = Join-Path $candidate $name
                if (Test-Path -LiteralPath $file -PathType Leaf) { (Resolve-Path -LiteralPath $file).ProviderPath }
            }
        }
    }
    $onPath = foreach ($name in $names) { Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source }

    foreach ($file in @($candidates) + @($onPath)) {
        if (-not $file) { continue }
        if (Test-NSPProcmonSignature -Path $file) { return $file }
        Write-Warning "Skipping $file - it is not validly signed by Microsoft."
    }
}
