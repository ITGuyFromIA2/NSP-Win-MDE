function Start-NSPProcmonCapture {
    <#
    .SYNOPSIS
        Starts a background Process Monitor capture to a backing file (.pml), optionally with a
        display filter and a run time. Returns a capture object for Stop-NSPProcmonCapture.

    .DESCRIPTION
        ProcMon runs minimized and quiet (/AcceptEula /Quiet /Minimized /BackingFile). It is a
        window of its own - it can't run inside the console - but nothing needs doing in it: the
        tech reproduces the problem in the app, then stops the capture from the console.

        Needs elevation (ProcMon loads a driver). Only one ProcMon can capture at a time, so this
        refuses to start while another is running. The capture keeps every event; -FilterPath only
        sets what ProcMon shows if someone opens it. A capture grows by hundreds of MB a minute on
        a busy machine - keep it short, or use -RuntimeSeconds.

    .PARAMETER ProcmonPath
        Process Monitor executable (Find-NSPProcmon).

    .PARAMETER OutputDirectory
        Folder for the backing file.

    .PARAMETER FilterPath
        A .pmc filter to load (New-NSPProcmonFilter).

    .PARAMETER RuntimeSeconds
        Stop by itself after this many seconds (0: run until Stop-NSPProcmonCapture).

    .PARAMETER MinimumFreeGB
        Warn when the output drive has less free space than this.

    .EXAMPLE
        $c = Start-NSPProcmonCapture -ProcmonPath (Find-NSPProcmon) -OutputDirectory C:\Temp -RuntimeSeconds 300

    .EXAMPLE
        Start-NSPProcmonCapture -ProcmonPath C:\Tools\Procmon64.exe -OutputDirectory D:\Captures -FilterPath D:\Captures\Violations.pmc
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ProcmonPath,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [string]$FilterPath,
        [ValidateRange(0, 86400)][int]$RuntimeSeconds = 0,
        [int]$MinimumFreeGB = 5
    )

    if (-not (Test-NSPProcmonSignature -Path $ProcmonPath)) { throw "$ProcmonPath is not validly signed by Microsoft - not starting it." }
    $running = @(Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue)
    if ($running) { throw "Process Monitor is already running (PID $(@($running.Id) -join ', ')). Close it, or stop it with Stop-NSPProcmonCapture, first." }
    if ($FilterPath -and -not (Test-Path -LiteralPath $FilterPath -PathType Leaf)) { throw "Filter file not found: $FilterPath" }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
    $root = [IO.Path]::GetPathRoot($OutputDirectory)
    try {
        $free = (New-Object IO.DriveInfo($root)).AvailableFreeSpace / 1GB
        if ($free -lt $MinimumFreeGB) { Write-Warning ("Only {0:N1} GB free on {1} - a capture can fill it quickly." -f $free, $root) }
    } catch { Write-Verbose "Free space on $root unknown: $($_.Exception.Message)" }

    $backing = Join-Path $OutputDirectory ("capture_{0}.pml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $arguments = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', $backing)
    if ($FilterPath) { $arguments += @('/LoadConfig', (Resolve-Path -LiteralPath $FilterPath).ProviderPath) }
    if ($RuntimeSeconds) { $arguments += @('/Runtime', [string]$RuntimeSeconds) }

    if (-not $PSCmdlet.ShouldProcess($backing, 'Start a ProcMon capture')) { return }
    $process = Invoke-NSPProcmonExe -FilePath $ProcmonPath -ArgumentList $arguments
    [pscustomobject][ordered]@{
        PSTypeName     = 'NSP.MDE.Capture'
        ProcmonPath    = $ProcmonPath
        ProcmonVersion = [string](Get-Item -LiteralPath $ProcmonPath).VersionInfo.ProductVersion
        BackingFile    = $backing
        FilterPath     = [string]$FilterPath
        RuntimeSeconds = $RuntimeSeconds
        ProcessId      = if ($process) { $process.Id } else { $null }
        Started        = Get-Date
        Ended          = $null
    }
}
