# Start-NSPMDETroubleshooter's screens. Each handler works on the session object
# ($script:MDESession) and returns to the menu; answers worth keeping between runs (company, app,
# processes, data folders, look-back) are saved in the MDE work folder.

function Save-NSPMDESessionAnswers {
    $s = $script:MDESession
    try {
        Save-NSPToolAnswers -Tool MDE -Answers ([pscustomobject][ordered]@{
                Company         = $s.Company
                ApplicationName = $s.ApplicationName
                ProcessNames    = @($s.ProcessNames)
                WatchPaths      = @($s.WatchPaths)
                LookbackDays    = $s.LookbackDays
                CaptureFolder   = $s.CaptureDir
            })
    } catch { Write-Warning "Answers not saved: $($_.Exception.Message)" }
}

function Wait-NSPMDEReturn { Read-Host 'Press Enter to return to the menu' | Out-Null }

function Split-NSPMDEList {
    # "a.exe, b.exe" -> @('a.exe','b.exe')
    param([AllowEmptyString()][string]$Text)
    @($Text -split '[,;]' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ } | Select-Object -Unique)
}

function Show-NSPMDEDashboard {
    $s = $script:MDESession
    Clear-NSPConsole
    Write-NSPConsoleHeader -Title 'MDE Troubleshooter - EDR sharing-violation evidence' -Subtitle "$env:COMPUTERNAME  $($s.VersionLabel)"
    $st = $s.Status
    if ($st) {
        $sensor = if ($st.SenseInstalled) { "MsSense $($st.MsSenseVersion) $($st.SenseState)" } else { 'Sense service not installed' }
        $onboard = if ($st.Onboarded) { 'onboarded' } else { 'NOT onboarded' }
        Write-NSPConsoleSegment -Segment @(@('  Sensor   ', 'Muted'), @("$sensor, $onboard", $(if ($st.Onboarded) { 'Success' } else { 'Warning' })),
            @('    AV ', 'Muted'), "$($st.AMRunningMode)", @('    Tamper ', 'Muted'), "$($st.IsTamperProtected)")
    }
    $app = if ($s.ApplicationName) { $s.ApplicationName } else { '(not set)' }
    Write-NSPConsoleSegment -Segment @(@('  App      ', 'Muted'), $app, @('    Processes ', 'Muted'), $(if ($s.ProcessNames) { $s.ProcessNames -join ', ' } else { '(none yet)' }))
    Write-NSPConsoleSegment -Segment @(@('  Folders  ', 'Muted'), $(if ($s.WatchPaths) { $s.WatchPaths -join ', ' } else { '(none yet - found by the capture)' }))
    $pm = if ($s.ProcmonPath) { $s.ProcmonPath } else { 'not found yet (downloaded when a capture starts)' }
    Write-NSPConsoleSegment -Segment @(@('  ProcMon  ', 'Muted'), $pm)
    Write-NSPConsoleSegment -Segment @(@('  Saving to ', 'Muted'), $s.CaptureDir)
    if ($s.Capture) {
        $state = if ($s.Capture.Ended) { "stopped $($s.Capture.Ended.ToString('HH:mm:ss'))" } else { "RUNNING since $($s.Capture.Started.ToString('HH:mm:ss'))" }
        Write-NSPConsoleSegment -Segment @(@('  Capture  ', 'Muted'), @($state, $(if ($s.Capture.Ended) { 'Normal' } else { 'Accent' })), @("  $($s.Capture.BackingFile)", 'Muted'))
    }
    if ($null -ne $s.Collisions) {
        $sum = Get-NSPMDEEvidenceSummary -Collision $s.Collisions
        $role = if ($sum.HeldByEdr) { 'Success' } elseif ($sum.Violations) { 'Warning' } else { 'Muted' }
        Write-NSPConsoleSegment -Segment @(@('  Evidence ', 'Muted'), @(("{0} violation(s), MsSense held {1}, MsMpEng held {2}" -f $sum.Violations, $sum.HeldByEdr, $sum.HeldByAv), $role))
    }
    Write-Host ''
}

function Resolve-NSPMDEProcmon {
    # The session's ProcMon, finding it - or with the tech's go-ahead downloading it - first.
    $s = $script:MDESession
    if ($s.ProcmonPath -and (Test-Path -LiteralPath $s.ProcmonPath)) { return $s.ProcmonPath }
    $s.ProcmonPath = Find-NSPProcmon
    if ($s.ProcmonPath) { return $s.ProcmonPath }
    Write-NSPConsoleLine 'Process Monitor was not found on this machine.' -Role Warning
    if (-not (Read-NSPConfirm -Prompt 'Download it from live.sysinternals.com (Microsoft-signed, checked before use)?' -DefaultYes)) { return $null }
    try {
        $s.ProcmonPath = Save-NSPProcmon -Confirm:$false
        Write-NSPConsoleLine "Saved $($s.ProcmonPath) (signature checked)." -Role Success
    } catch { Write-NSPConsoleLine "Download failed: $($_.Exception.Message)" -Role Error }
    return $s.ProcmonPath
}

function Write-NSPMDEFilters {
    # The filter files for this session, from the current process names and data folders.
    $s = $script:MDESession
    $dir = $s.CaptureDir
    $s.Filters = [ordered]@{ Violations = (New-NSPProcmonFilter -Kind Violations -OutputPath (Join-Path $dir 'NSP_SharingViolations.pmc') -Confirm:$false).FullName }
    $s.Filters['Processes'] = (New-NSPProcmonFilter -Kind Processes -ProcessName $s.ProcessNames -OutputPath (Join-Path $dir 'NSP_AppAndEdr.pmc') -Confirm:$false).FullName
    if ($s.WatchPaths) { $s.Filters['Activity'] = (New-NSPProcmonFilter -Kind Activity -Path $s.WatchPaths -OutputPath (Join-Path $dir 'NSP_ShareFileActivity.pmc') -Confirm:$false).FullName }
}

# ---------------------------------------------------------------------------
function Invoke-NSPMDEMenuStatus {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Defender for Endpoint status'
    $s.Status = Get-NSPMDEStatus
    $s.Status | Format-List ComputerName, OperatingSystem, SenseInstalled, SenseState, SenseStartMode, MsSensePath, MsSenseVersion, Onboarded, OrgId,
    AMRunningMode, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, RealTimeProtectionEnabled, IsTamperProtected, ExclusionsVisible | Out-Host
    if ($s.Status.ExclusionsVisible) {
        Write-NSPConsoleLine 'Antivirus exclusions (these do NOT apply to the EDR sensor):' -Role Strong
        foreach ($name in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
            Write-Host ("  {0,-20} {1}" -f $name, $(if ($s.Status.$name) { $s.Status.$name -join '; ' } else { '(none)' }))
        }
    } else {
        Write-NSPConsoleLine 'Exclusion lists are hidden (not elevated).' -Role Muted
    }
    if (-not $s.Status.Onboarded) { Write-NSPConsoleLine 'This machine is not onboarded to Defender for Endpoint - an EDR exclusion would not apply here.' -Role Warning }
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuCrashes {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Crash and hang events'
    Write-NSPConsoleLine 'Finds the executables that crash or hang. The data files they fight over show up in the capture.' -Role Muted
    $days = Read-NSPOptional -Prompt 'Look back how many days' -Default ([string]$s.LookbackDays)
    $n = 0; if ([int]::TryParse($days, [ref]$n) -and $n -gt 0) { $s.LookbackDays = $n }
    Write-NSPConsoleLine "Reading the Application log ($($s.LookbackDays) days)..." -Role Muted
    $events = @(Get-NSPMDECrashEvent -Days $s.LookbackDays)
    $s.CrashEvents = $events
    $candidates = @($events | Get-NSPMDECandidateApp)
    if (-not $candidates) {
        Write-NSPConsoleLine 'No crash or hang events in that window. Enter the app''s executable names in the filter step instead.' -Role Warning
        Wait-NSPMDEReturn; return
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $events | Sort-Object TimeCreated | Export-Csv -LiteralPath (Join-Path $s.CaptureDir "crash-events_$stamp.csv") -NoTypeInformation -Encoding UTF8

    for ($i = 0; $i -lt $candidates.Count -and $i -lt 20; $i++) {
        $c = $candidates[$i]
        Write-NSPConsoleLine ('  {0,2}. ' -f ($i + 1)) -Role Key -NoNewline
        Write-Host ('{0,-32} {1,4} hit(s)  last {2:yyyy-MM-dd HH:mm}  {3}' -f $c.ExeName, $c.Hits, $c.LastSeen, (@($c.ExePaths) -join '; '))
    }
    Write-Host ''
    $pick = Read-NSPOptional -Prompt 'Which are the app (numbers, comma-separated; blank keeps the current list)'
    if ($pick) {
        $chosen = @(foreach ($p in Split-NSPMDEList $pick) { $k = 0; if ([int]::TryParse($p, [ref]$k) -and $k -ge 1 -and $k -le $candidates.Count) { $candidates[$k - 1] } })
        if ($chosen) {
            $s.Candidates = $chosen
            $s.ProcessNames = @($chosen.ExeName)
        }
    }
    if (-not $s.ApplicationName) { $s.ApplicationName = Read-NSPOptional -Prompt 'App name as the client knows it (e.g. Sage 100)' }
    Save-NSPMDESessionAnswers
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuFilter {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'ProcMon filters'
    Write-NSPConsoleLine 'Three filters are written: violations only (the proof), app + Defender, and file activity in the data folders.' -Role Muted
    Write-NSPConsoleLine 'They only change what ProcMon shows - the capture keeps everything and the analysis reads it all.' -Role Muted
    Write-Host ''
    $current = $s.ProcessNames -join ', '
    $s.ProcessNames = Split-NSPMDEList (Read-NSPOptional -Prompt 'App executable names (comma-separated)' -Default $current)
    $current = $s.WatchPaths -join ', '
    Write-NSPConsoleLine 'Data-folder fragments match anywhere in a path, e.g. \Clients\ or \DATA\ (blank if not known yet).' -Role Muted
    $s.WatchPaths = Split-NSPMDEList (Read-NSPOptional -Prompt 'Data-folder fragments (comma-separated)' -Default $current)
    if (-not $s.ApplicationName) { $s.ApplicationName = Read-NSPOptional -Prompt 'App name as the client knows it (e.g. Sage 100)' }
    Write-NSPMDEFilters
    foreach ($k in $s.Filters.Keys) { Write-NSPConsoleLine ("  {0,-11} {1}" -f $k, $s.Filters[$k]) -Role Success }
    Save-NSPMDESessionAnswers
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuStart {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Start capture'
    if ($s.Capture -and -not $s.Capture.Ended) { Write-NSPConsoleLine 'A capture is already running - stop it first.' -Role Warning; Wait-NSPMDEReturn; return }
    $exe = Resolve-NSPMDEProcmon
    if (-not $exe) { Wait-NSPMDEReturn; return }
    if (-not $s.Filters) { Write-NSPMDEFilters }
    $display = if ($s.Filters.Contains('Activity')) { $s.Filters['Activity'] } else { $s.Filters['Processes'] }

    Write-NSPConsoleLine 'A capture grows by hundreds of MB a minute on a busy machine. Keep it to the reproduction.' -Role Muted
    $minutes = Read-NSPOptional -Prompt 'Stop by itself after how many minutes (blank: until you stop it)'
    $seconds = 0; $m = 0; if ([int]::TryParse($minutes, [ref]$m) -and $m -gt 0) { $seconds = $m * 60 }
    try {
        $s.Capture = Start-NSPProcmonCapture -ProcmonPath $exe -OutputDirectory $s.CaptureDir -FilterPath $display -RuntimeSeconds $seconds -Confirm:$false
        $s.Collisions = $null
    } catch { Write-NSPConsoleLine "Could not start: $($_.Exception.Message)" -Role Error; Wait-NSPMDEReturn; return }
    Write-Host ''
    Write-NSPConsoleLine "Capturing to $($s.Capture.BackingFile)" -Role Success
    Write-NSPConsoleLine 'Now reproduce the failure in the app (save the record, post the batch, ...).' -Role Strong
    Write-NSPConsoleLine 'When it has failed at least once, come back and choose "Stop capture and analyze".' -Role Strong
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEAnalysis {
    # Exports a capture, finds the collisions, and shows the verdict.
    param([Parameter(Mandatory)][string]$Path)
    $s = $script:MDESession
    $exe = $null
    if ([IO.Path]::GetExtension($Path) -ieq '.pml') {
        $exe = Resolve-NSPMDEProcmon
        if (-not $exe) { return }
        Write-NSPConsoleLine 'Exporting the capture (file opens and closes) - this can take a few minutes...' -Role Muted
    }
    try {
        $events = ConvertFrom-NSPProcmonLog -Path $Path -ProcmonPath $exe
        $s.Collisions = @($events | Find-NSPMDECollision)
    } catch { Write-NSPConsoleLine "Analysis failed: $($_.Exception.Message)" -Role Error; return }

    $sum = Get-NSPMDEEvidenceSummary -Collision $s.Collisions
    Write-Host ''
    Write-NSPConsoleLine ("App sharing violations: {0}   held by MsSense (EDR): {1}   MsMpEng (AV): {2}   other: {3}   holder not seen: {4}" -f $sum.Violations, $sum.HeldByEdr, $sum.HeldByAv, $sum.HeldByOther, $sum.HolderNotSeen) -Role Strong
    if ($sum.DefenderRefused) { Write-NSPConsoleLine "($($sum.DefenderRefused) more where Defender itself was refused - harmless to the app, not counted.)" -Role Muted }
    Write-NSPConsoleLine $sum.Verdict -Role $(if ($sum.HeldByEdr) { 'Success' } else { 'Warning' })
    $app = @(Select-NSPMDEAppCollision -Collision $s.Collisions)
    if ($app) {
        Write-Host ''
        $app | Sort-Object @{ e = { $_.HolderKind -ne 'EDR' } }, Sequence | Select-Object -First 15 Time, ProcessName, HolderKind,
        @{ n = 'Holder'; e = { @($_.Holders | ForEach-Object { "$($_.ProcessName) ($($_.HeldMs) ms)" }) -join ', ' } }, ShareMode, Path |
            Format-Table -AutoSize -Wrap | Out-Host
        # New data folders the tech didn't know about: offer them for the activity filter.
        $folders = @($app | ForEach-Object { Split-Path -Parent $_.Path } | Where-Object { $_ } | Sort-Object -Unique)
        if ($folders -and -not $s.WatchPaths) {
            Write-NSPConsoleLine "Contested folders: $($folders -join ', ')" -Role Muted
            if (Read-NSPConfirm -Prompt 'Use them as the data folders for the activity filter?' -DefaultYes) {
                $s.WatchPaths = @($folders | ForEach-Object { $_ + '\' })
                Write-NSPMDEFilters
                Save-NSPMDESessionAnswers
            }
        }
    }
}

function Invoke-NSPMDEMenuStop {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Stop capture and analyze'
    if (-not $s.Capture) { Write-NSPConsoleLine 'No capture in this session - use "Analyze an existing capture" for one from earlier.' -Role Warning; Wait-NSPMDEReturn; return }
    if (-not $s.Capture.Ended) {
        Write-NSPConsoleLine 'Stopping ProcMon and waiting for it to finish writing...' -Role Muted
        try { $s.Capture = $s.Capture | Stop-NSPProcmonCapture -Confirm:$false } catch { Write-NSPConsoleLine "Stop failed: $($_.Exception.Message)" -Role Error; Wait-NSPMDEReturn; return }
    }
    if (Test-Path -LiteralPath $s.Capture.BackingFile) {
        Write-NSPConsoleLine ("Capture: {0} ({1:N0} MB)" -f $s.Capture.BackingFile, ((Get-Item -LiteralPath $s.Capture.BackingFile).Length / 1MB)) -Role Muted
        if ($s.Capture.PSObject.Properties['Incomplete'] -and $s.Capture.Incomplete) {
            Write-NSPConsoleLine ("ProcMon wrote an incomplete capture: it covers only {0:N0} seconds. Start a new capture and reproduce again." -f $s.Capture.CoveredSeconds) -Role Error
            Write-NSPConsoleLine 'Analyzing what is there, but "no violations" from this capture proves nothing.' -Role Warning
        }
        Invoke-NSPMDEAnalysis -Path $s.Capture.BackingFile
    }
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuAnalyze {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Analyze an existing capture'
    Write-NSPConsoleLine 'A ProcMon .pml, or a .csv saved from ProcMon with its default columns.' -Role Muted
    $path = $null
    if ($s.Capture -and $s.Capture.BackingFile -and (Test-Path -LiteralPath $s.Capture.BackingFile) -and
        (Read-NSPConfirm -Prompt "This session's capture ($(Split-Path -Leaf $s.Capture.BackingFile))?" -DefaultYes)) {
        $path = $s.Capture.BackingFile
    } else {
        $path = Read-NSPFilePath -Prompt 'Capture file' -Filter 'ProcMon captures (*.pml;*.csv)|*.pml;*.csv|All files (*.*)|*.*' -InitialDirectory $s.CaptureDir -AllowBack
        if (Test-NSPBackSignal $path) { return }
    }
    if (-not $s.Capture -or $s.Capture.BackingFile -ne $path) {
        $item = Get-Item -LiteralPath $path
        $s.Capture = [pscustomobject][ordered]@{
            PSTypeName = 'NSP.MDE.Capture'; ProcmonPath = $s.ProcmonPath; ProcmonVersion = ''; BackingFile = $(if ($item.Extension -ieq '.pml') { $item.FullName } else { '' })
            FilterPath = ''; RuntimeSeconds = 0; ProcessId = $null; Started = $null; Ended = $item.LastWriteTime
        }
    }
    Invoke-NSPMDEAnalysis -Path $path
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuFolder {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Capture folder'
    if ($s.Capture -and -not $s.Capture.Ended) { Write-NSPConsoleLine 'A capture is running - stop it first.' -Role Warning; Wait-NSPMDEReturn; return }
    Write-NSPConsoleLine 'Captures, filters and crash-event CSVs go here. A capture can grow by hundreds of MB a minute - pick a drive with room.' -Role Muted
    $dir = Read-NSPFolderPath -Prompt 'Capture folder' -Default $s.CaptureDir -Create -AllowBack
    if (Test-NSPBackSignal $dir) { return }
    if ($dir -ne $s.CaptureDir) {
        $s.CaptureDir = $dir
        $s.Filters = $null   # rewritten into the new folder when next needed
        Save-NSPMDESessionAnswers
    }
    try {
        $free = (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($dir))).AvailableFreeSpace / 1GB
        Write-NSPConsoleLine ("Capture folder: {0} ({1:N1} GB free)" -f $dir, $free) -Role Success
    } catch { Write-NSPConsoleLine "Capture folder: $dir" -Role Success }
    Wait-NSPMDEReturn
}

function Invoke-NSPMDEMenuView {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Open the capture in ProcMon'
    if (-not $s.Capture -or -not $s.Capture.BackingFile -or -not (Test-Path -LiteralPath $s.Capture.BackingFile)) { Write-NSPConsoleLine 'No .pml capture to open.' -Role Warning; Wait-NSPMDEReturn; return }
    if (-not $s.Capture.Ended) { Write-NSPConsoleLine 'Stop the capture first.' -Role Warning; Wait-NSPMDEReturn; return }
    $exe = Resolve-NSPMDEProcmon
    if (-not $exe) { Wait-NSPMDEReturn; return }
    if (-not $s.Filters) { Write-NSPMDEFilters }
    Write-NSPConsoleLine 'For screenshots in the support case: the violations view first, then the activity view showing the MsSense handle around it.' -Role Muted
    $choices = @(foreach ($k in $s.Filters.Keys) { [pscustomobject]@{ Label = $k; Value = $s.Filters[$k] } })
    $filter = Read-NSPChoice -Choices $choices -Prompt 'Filter to open with'
    if (-not $filter) { return }
    $null = Invoke-NSPProcmonExe -FilePath $exe -ArgumentList @('/AcceptEula', '/OpenLog', $s.Capture.BackingFile, '/LoadConfig', $filter)
}

function Invoke-NSPMDEMenuHandoff {
    $s = $script:MDESession
    Write-NSPConsoleHeader 'Write the hand-back'
    Write-NSPConsoleLine 'Writes <Company>_MDE_Response.json: Defender facts, candidate apps, the capture, the collision evidence and its verdict.' -Role Muted
    Write-NSPConsoleLine 'The ProcMon files stay next to the capture; attach the .pml to the support case if asked.' -Role Muted
    Write-Host ''
    $company = ''
    while (-not $company) { $company = Read-NSPOptional -Prompt 'Company' -Default $s.Company }
    $s.Company = $company
    $s.ApplicationName = Read-NSPOptional -Prompt 'App name as the client knows it' -Default $s.ApplicationName
    $notes = Read-NSPOptional -Prompt 'Notes for the request (what the users see, when it started; blank for none)'
    Save-NSPMDESessionAnswers
    if (-not $s.Status) { $s.Status = Get-NSPMDEStatus }
    $candidates = if ($s.Candidates) { $s.Candidates } elseif ($s.CrashEvents) { @($s.CrashEvents | Get-NSPMDECandidateApp -ProcessName $s.ProcessNames) } else { @() }
    try {
        $file = Export-NSPMDEResponse -Company $company -ApplicationName $s.ApplicationName -Status $s.Status -Candidate $candidates `
            -Capture $s.Capture -Collision $s.Collisions -TechNotes $notes -Confirm:$false
    } catch { Write-NSPConsoleLine "ERROR: $($_.Exception.Message)" -Role Error; Wait-NSPMDEReturn; return }
    Write-Host ''
    Write-NSPConsoleLine "Written: $($file.FullName)" -Role Success
    if ($null -eq $s.Collisions) { Write-NSPConsoleLine 'No capture was analyzed - the file has the Defender facts and candidates only.' -Role Warning }
    Write-NSPConsoleLine 'Copy it back for the EDR exclusion request.' -Role Strong
    Open-NSPOutputFolder -Path $file.FullName
    Wait-NSPMDEReturn
}
