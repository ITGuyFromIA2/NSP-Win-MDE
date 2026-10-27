function Get-NSPMDEStatus {
    <#
    .SYNOPSIS
        Defender for Endpoint facts for this machine: the EDR sensor (Sense service, MsSense.exe
        path and version, onboarding state, org ID) and the antivirus side (running mode, versions,
        real-time and tamper protection, exclusions).

    .DESCRIPTION
        Read-only. Runs without elevation, but Defender only shows its exclusion lists to an
        administrator - ExclusionsVisible says whether the lists are real or hidden.

        The EDR sensor (MsSense.exe) and the antivirus engine (MsMpEng.exe) are separate: an
        antivirus exclusion does not stop the sensor opening a file. Both are reported so the
        evidence can show which one is involved.

    .EXAMPLE
        Get-NSPMDEStatus

    .EXAMPLE
        (Get-NSPMDEStatus).MsSenseVersion
    #>
    [CmdletBinding()]
    param()

    $sense = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sense'" -ErrorAction SilentlyContinue
    $msSense = $null
    if ($sense -and $sense.PathName) {
        $msSense = [Environment]::ExpandEnvironmentVariables(($sense.PathName -replace '^\s*"([^"]+)".*$', '$1'))
    }
    $msSenseVersion = ''
    if ($msSense -and (Test-Path -LiteralPath $msSense -PathType Leaf -ErrorAction SilentlyContinue)) { $msSenseVersion = [string](Get-Item -LiteralPath $msSense).VersionInfo.ProductVersion }
    # Without elevation the platform folder can't be read; its name carries the version
    # (...\Platform\Versions\10.8838.26060.15013-0\MsSense.exe).
    if (-not $msSenseVersion -and $msSense -match '\\Versions\\(?<v>\d+(?:\.\d+){1,3})(?:-\d+)?\\[^\\]+$') { $msSenseVersion = $Matches.v }

    $atp = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
    $onboarding = if ($atp -and $null -ne $atp.OnboardingState) { [int]$atp.OnboardingState } else { $null }

    $mp = $null
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { Write-Verbose "Get-MpComputerStatus: $($_.Exception.Message)" }
    }
    $pref = $null
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try { $pref = Get-MpPreference -ErrorAction Stop } catch { Write-Verbose "Get-MpPreference: $($_.Exception.Message)" }
    }
    # Without elevation Defender returns a single placeholder string instead of the list.
    $hidden = { param($List) [bool](@($List) | Where-Object { "$_" -like 'N/A:*' }) }
    $exclusionsVisible = [bool]$pref -and -not ((& $hidden $pref.ExclusionPath) -or (& $hidden $pref.ExclusionProcess) -or (& $hidden $pref.ExclusionExtension))
    $list = { param($List) if ($exclusionsVisible) { @($List | Where-Object { $_ }) } else { @() } }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $mpValue = { param($Name) if ($mp -and $mp.PSObject.Properties[$Name]) { $mp.$Name } else { $null } }

    [pscustomobject][ordered]@{
        PSTypeName                = 'NSP.MDE.Status'
        ComputerName              = $env:COMPUTERNAME
        OperatingSystem           = if ($os) { "$($os.Caption) ($($os.Version))" } else { '' }
        SenseInstalled            = [bool]$sense
        SenseState                = if ($sense) { [string]$sense.State } else { '' }
        SenseStartMode            = if ($sense) { [string]$sense.StartMode } else { '' }
        MsSensePath               = [string]$msSense
        MsSenseVersion            = $msSenseVersion
        Onboarded                 = ($onboarding -eq 1)
        OnboardingState           = $onboarding
        OrgId                     = if ($atp) { [string]$atp.OrgId } else { '' }
        AMRunningMode             = [string](& $mpValue 'AMRunningMode')
        AMProductVersion          = [string](& $mpValue 'AMProductVersion')
        AMEngineVersion           = [string](& $mpValue 'AMEngineVersion')
        AntivirusSignatureVersion = [string](& $mpValue 'AntivirusSignatureVersion')
        AntivirusEnabled          = & $mpValue 'AntivirusEnabled'
        RealTimeProtectionEnabled = & $mpValue 'RealTimeProtectionEnabled'
        IsTamperProtected         = & $mpValue 'IsTamperProtected'
        ExclusionsVisible         = $exclusionsVisible
        ExclusionPath             = & $list $pref.ExclusionPath
        ExclusionProcess          = & $list $pref.ExclusionProcess
        ExclusionExtension        = & $list $pref.ExclusionExtension
    }
}
