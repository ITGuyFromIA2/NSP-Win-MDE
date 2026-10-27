<#
    The MDE hand-back payload (Schema 1), carried in an NSP.Toolkit Response hand-off as
    <Company>_MDE_Response.json. The tech brings it back to fill in the EDR exclusion request.

      SchemaVersion, Tool, ToolVersion, Generated, Company, ComputerName, Domain, OperatingSystem
      Mde            Get-NSPMDEStatus facts (sensor, onboarding, AV mode and versions, exclusions)
      Application    Name (as the tech knows it), Candidates (Get-NSPMDECandidateApp)
      Capture        ProcMon version, start/end, backing-file name, size and SHA-256, CSV name
      Evidence       Violations (the app refused), HeldByEdr, HeldByAv, HeldByOther, HolderNotSeen,
                     DefenderRefused (Defender refused - not evidence, not in the lists), Verdict,
                     ContestedPaths (path, violations, processes, holders),
                     Collisions (the first -MaxCollisions, holders included)
      SuggestedExclusion  Processes (the violating executables, full paths where known),
                     Folders (the contested files' folders) - a starting point, not a decision
      TechNotes
#>

$script:NSPMDEResponseSchema = 1

function Select-NSPMDEAppCollision {
    # PURE. The collisions that count as evidence: the app was refused. Defender itself being
    # refused (reading a file the app holds exclusively) is harmless to the app.
    param([AllowNull()][object[]]$Collision)
    @($Collision | Where-Object { $_ -and $_.ProcessKind -notin 'EDR', 'AV' })
}

function Get-NSPMDEEvidenceSummary {
    # PURE. Counts and the one-line verdict for a set of collisions.
    param([AllowNull()][object[]]$Collision)
    $defenderRefused = @($Collision | Where-Object { $_ -and $_.ProcessKind -in 'EDR', 'AV' }).Count
    $all = @(Select-NSPMDEAppCollision -Collision $Collision)
    $edr = @($all | Where-Object HolderKind -eq 'EDR').Count
    $av = @($all | Where-Object HolderKind -eq 'AV').Count
    $other = @($all | Where-Object HolderKind -eq 'Other').Count
    $notSeen = @($all | Where-Object HolderKind -eq 'NotSeen').Count
    $verdict = if (-not $all.Count) {
        'No sharing violations were captured. Reproduce the failure during a capture.'
    } elseif ($edr) {
        "The EDR sensor (MsSense.exe) held the file in $edr of $($all.Count) sharing violation(s). An antivirus exclusion will not stop the sensor; a Defender for Endpoint EDR (Sense) exclusion is required."
    } elseif ($av) {
        "The antivirus engine (MsMpEng.exe) held the file in $av of $($all.Count) sharing violation(s), the sensor in none. A Defender antivirus exclusion should resolve it; this does not support an EDR exclusion request."
    } elseif ($other) {
        "Sharing violations were captured, but Defender held none of the files ($other held by other processes)."
    } else {
        "Sharing violations were captured, but the holder opened the file before the capture began. Start the capture before the app opens the file."
    }
    [pscustomobject][ordered]@{
        Violations      = $all.Count
        HeldByEdr       = $edr
        HeldByAv        = $av
        HeldByOther     = $other
        HolderNotSeen   = $notSeen
        DefenderRefused = $defenderRefused
        Verdict         = $verdict
    }
}

function New-NSPMDEResponsePayload {
    # PURE apart from the clock and host facts. Builds the Schema 1 object.
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Company,
        [string]$ApplicationName,
        $Status,
        [object[]]$Candidate,
        $Capture,
        [object[]]$Collision,
        [string]$TechNotes,
        [int]$MaxCollisions = 25,
        [string]$ToolVersion = '',
        [string]$BackingFileSha256 = '',
        [Nullable[long]]$BackingFileBytes = $null,
        [string]$CsvFile = ''
    )

    $summary = Get-NSPMDEEvidenceSummary -Collision $Collision
    $collisions = @(Select-NSPMDEAppCollision -Collision $Collision)
    $candidates = @($Candidate | Where-Object { $_ })

    $contested = @($collisions | Group-Object Path | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject][ordered]@{
                Path       = $_.Name
                Violations = $_.Count
                Processes  = @($_.Group.ProcessName | Sort-Object -Unique)
                Holders    = @($_.Group | ForEach-Object { $_.Holders } | ForEach-Object ProcessName | Sort-Object -Unique)
            }
        })

    # Full paths for the violating executables where the crash events supplied them.
    $exePaths = @{}
    foreach ($c in $candidates) { foreach ($p in @($c.ExePaths)) { if ($p) { $exePaths[[string]$c.ExeName] = [string]$p } } }
    $processes = @($collisions | Where-Object { $_.HolderKind -in 'EDR', 'AV' } | ForEach-Object ProcessName | Sort-Object -Unique | ForEach-Object {
            if ($exePaths.ContainsKey($_)) { $exePaths[$_] } else { $_ }
        })
    $folders = @($collisions | Where-Object { $_.HolderKind -in 'EDR', 'AV' } | ForEach-Object {
            $parent = Split-Path -Parent ([string]$_.Path)
            if ($parent) { $parent + '\' }
        } | Sort-Object -Unique)

    $statusFields = 'MsSensePath', 'MsSenseVersion', 'SenseState', 'SenseStartMode', 'Onboarded', 'OnboardingState', 'OrgId',
    'AMRunningMode', 'AMProductVersion', 'AMEngineVersion', 'AntivirusSignatureVersion', 'AntivirusEnabled',
    'RealTimeProtectionEnabled', 'IsTamperProtected', 'ExclusionsVisible', 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension'
    $mde = [ordered]@{}
    foreach ($f in $statusFields) { $mde[$f] = if ($Status -and $Status.PSObject.Properties[$f]) { $Status.$f } else { $null } }

    $domain = try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name } catch { "$env:USERDNSDOMAIN" }
    [pscustomobject][ordered]@{
        SchemaVersion      = $script:NSPMDEResponseSchema
        Tool               = 'NSP.Win.MDE'
        ToolVersion        = $ToolVersion
        Generated          = (Get-Date).ToString('s')
        Company            = $Company
        ComputerName       = "$env:COMPUTERNAME"
        Domain             = $domain
        OperatingSystem    = if ($Status) { [string]$Status.OperatingSystem } else { '' }
        Mde                = [pscustomobject]$mde
        Application        = [pscustomobject][ordered]@{
            Name       = [string]$ApplicationName
            Candidates = @($candidates | ForEach-Object {
                    [pscustomobject][ordered]@{
                        ExeName        = [string]$_.ExeName
                        Hits           = $_.Hits
                        ExePaths       = @($_.ExePaths)
                        FirstSeen      = if ($_.FirstSeen) { ([datetime]$_.FirstSeen).ToString('s') } else { '' }
                        LastSeen       = if ($_.LastSeen) { ([datetime]$_.LastSeen).ToString('s') } else { '' }
                        ExceptionCodes = @($_.ExceptionCodes)
                        EventIds       = @($_.EventIds)
                    }
                })
        }
        Capture            = if ($Capture) {
            [pscustomobject][ordered]@{
                ProcmonVersion    = [string]$Capture.ProcmonVersion
                Started           = if ($Capture.Started) { ([datetime]$Capture.Started).ToString('s') } else { '' }
                Ended             = if ($Capture.Ended) { ([datetime]$Capture.Ended).ToString('s') } else { '' }
                BackingFile       = if ($Capture.BackingFile) { Split-Path -Leaf $Capture.BackingFile } else { '' }
                BackingFileBytes  = $BackingFileBytes
                BackingFileSha256 = $BackingFileSha256
                CsvFile           = $CsvFile
                CoveredSeconds    = if ($Capture.PSObject.Properties['CoveredSeconds']) { $Capture.CoveredSeconds } else { $null }
                Incomplete        = if ($Capture.PSObject.Properties['Incomplete']) { [bool]$Capture.Incomplete } else { $null }
            }
        } else { $null }
        Evidence           = [pscustomobject][ordered]@{
            Violations     = $summary.Violations
            HeldByEdr      = $summary.HeldByEdr
            HeldByAv       = $summary.HeldByAv
            HeldByOther    = $summary.HeldByOther
            HolderNotSeen  = $summary.HolderNotSeen
            DefenderRefused = $summary.DefenderRefused
            Verdict        = $summary.Verdict
            ContestedPaths = $contested
            Collisions     = @($collisions | Select-Object -First $MaxCollisions | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Time          = $_.Time
                        ProcessName   = $_.ProcessName
                        PID           = $_.PID
                        Path          = $_.Path
                        DesiredAccess = $_.DesiredAccess
                        ShareMode     = $_.ShareMode
                        HolderKind    = $_.HolderKind
                        Holders       = @($_.Holders)
                    }
                })
        }
        SuggestedExclusion = [pscustomobject][ordered]@{
            Processes = $processes
            Folders   = $folders
        }
        TechNotes          = [string]$TechNotes
    }
}
