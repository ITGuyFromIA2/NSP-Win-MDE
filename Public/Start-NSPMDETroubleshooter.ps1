function Start-NSPMDETroubleshooter {
    <#
    .SYNOPSIS
        The MDE Troubleshooter menu: gather the evidence that Microsoft Defender for Endpoint's EDR
        sensor (MsSense.exe) collides with a line-of-business app, for an EDR exclusion request -
        Defender status, crash/hang events, ProcMon filters, a capture, the collision analysis, and
        the JSON hand-back.

    .DESCRIPTION
        Run it on the machine where the app fails (over a remote session is fine). Typical flow:
          1 status, 2 crash events (pick the app), 3 filters, 4 start capture -> the user
          reproduces the failure -> 5 stop and analyze, 7 open in ProcMon for screenshots,
          8 write the hand-back.
        Relaunches elevated if needed. Captures go to the MDE work folder
        (%ProgramData%\NSP\Toolkit\MDE\Captures) unless -OutputRoot says otherwise; answers
        (company, app, processes, data folders) are remembered between runs.

    .PARAMETER OutputRoot
        Folder for captures, filters and the crash-event CSVs (a drive with room to spare).

    .PARAMETER SeedAnswersJson
        Answers to merge in (Company, ApplicationName, ProcessNames, WatchPaths, LookbackDays).

    .PARAMETER SeedOnly
        Merge -SeedAnswersJson and return without opening the menu.

    .PARAMETER NoElevate
        Do not relaunch elevated.

    .EXAMPLE
        Start-NSPMDETroubleshooter

    .EXAMPLE
        Start-NSPMDETroubleshooter -OutputRoot 'D:\MDECaptures'
    #>
    [CmdletBinding()]
    param(
        [string]$OutputRoot,
        [string]$SeedAnswersJson,
        [switch]$SeedOnly,
        [switch]$NoElevate
    )

    Use-NSPMDEDependency

    if ($SeedOnly) {
        $null = Import-NSPToolSeedAnswers -Tool MDE -SeedAnswersJson $SeedAnswersJson
        return
    }

    if (-not $NoElevate) {
        $manifest = (Join-Path $script:ModuleRoot 'NSP.Win.MDE.psd1').Replace("'", "''")
        $relaunch = "Import-Module '$manifest'; Start-NSPMDETroubleshooter"
        if ($PSBoundParameters.ContainsKey('OutputRoot')) { $relaunch += " -OutputRoot '$($OutputRoot.Replace("'", "''"))'" }
        if (Invoke-NSPElevated -Command $relaunch -NoExit) { return }
    }
    $saved = Import-NSPToolSeedAnswers -Tool MDE -SeedAnswersJson $SeedAnswersJson
    $savedValue = { param($Name) if ($saved -and $saved.PSObject.Properties[$Name]) { $saved.$Name } else { $null } }

    if (-not $OutputRoot) { $OutputRoot = [string](& $savedValue 'CaptureFolder') }
    if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-NSPToolWorkPath -Tool MDE -Create) 'Captures' }
    if (-not (Test-Path -LiteralPath $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }

    $version = [string]$ExecutionContext.SessionState.Module.Version
    $days = [int](& $savedValue 'LookbackDays'); if ($days -le 0) { $days = 14 }
    $script:MDESession = [pscustomobject]@{
        VersionLabel    = (Get-NSPToolVersionStatus -ToolKey 'NSP.Win.MDE' -Version $version).Label
        CaptureDir      = (Resolve-Path -LiteralPath $OutputRoot).ProviderPath
        Company         = [string](& $savedValue 'Company')
        ApplicationName = [string](& $savedValue 'ApplicationName')
        ProcessNames    = @(& $savedValue 'ProcessNames' | Where-Object { $_ })
        WatchPaths      = @(& $savedValue 'WatchPaths' | Where-Object { $_ })
        LookbackDays    = $days
        Status          = $null
        CrashEvents     = $null
        Candidates      = $null
        ProcmonPath     = $null
        Filters         = $null
        Capture         = $null
        Collisions      = $null
    }
    Set-NSPConsoleMaximized -ErrorAction SilentlyContinue
    $script:MDESession.Status = Get-NSPMDEStatus
    $script:MDESession.ProcmonPath = Find-NSPProcmon -WarningAction SilentlyContinue

    $choices = @(
        [pscustomobject]@{ Section = 'Evidence'; Label = 'Defender for Endpoint status'; Value = 'Status'; Help = 'Sensor version and onboarding, AV mode, tamper protection, exclusions.' }
        [pscustomobject]@{ Label = 'Crash and hang events'; Value = 'Crashes'; Help = 'Find the app executables that fail (Application log).' }
        [pscustomobject]@{ Label = 'ProcMon filters'; Value = 'Filter'; Help = 'App executables and data folders to watch.' }
        [pscustomobject]@{ Section = 'Capture'; Label = 'Start capture'; Value = 'Start'; Help = 'ProcMon runs minimized; the user reproduces the failure.' }
        [pscustomobject]@{ Label = 'Stop capture and analyze'; Value = 'Stop'; Help = 'Who held the file at each sharing violation: MsSense (EDR) or MsMpEng (AV)?' }
        [pscustomobject]@{ Label = 'Analyze an existing capture'; Value = 'Analyze'; Help = 'A .pml or ProcMon .csv from earlier.' }
        [pscustomobject]@{ Label = 'Open the capture in ProcMon'; Value = 'View'; Help = 'With a filter loaded, for screenshots in the support case.' }
        [pscustomobject]@{ Section = 'Hand back'; Label = 'Write the hand-back JSON'; Value = 'Handoff'; Help = '<Company>_MDE_Response.json for the EDR exclusion request.' }
        [pscustomobject]@{ Key = 'F'; Label = 'Capture folder'; Value = 'Folder'; Help = 'Where captures go (pick a drive with room).' }
    )

    while ($true) {
        Show-NSPMDEDashboard
        $choice = Read-NSPMenu -Choices $choices -CancelLabel 'Quit'
        if ($null -eq $choice) {
            $capture = $script:MDESession.Capture
            if ($capture -and -not $capture.Ended -and (Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue)) {
                if (Read-NSPConfirm -Prompt 'A capture is still running. Stop it before quitting?' -DefaultYes) { $null = $capture | Stop-NSPProcmonCapture -Confirm:$false }
            }
            Write-NSPConsoleLine 'Goodbye.' -Role Muted
            return
        }
        switch ($choice) {
            'Status' { Invoke-NSPMDEMenuStatus }
            'Crashes' { Invoke-NSPMDEMenuCrashes }
            'Filter' { Invoke-NSPMDEMenuFilter }
            'Start' { Invoke-NSPMDEMenuStart }
            'Stop' { Invoke-NSPMDEMenuStop }
            'Analyze' { Invoke-NSPMDEMenuAnalyze }
            'View' { Invoke-NSPMDEMenuView }
            'Handoff' { Invoke-NSPMDEMenuHandoff }
            'Folder' { Invoke-NSPMDEMenuFolder }
        }
    }
}
