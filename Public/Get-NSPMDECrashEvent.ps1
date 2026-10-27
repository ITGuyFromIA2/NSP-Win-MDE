function Get-NSPMDECrashEvent {
    <#
    .SYNOPSIS
        Application crash and hang events (Application Error 1000, Windows Error Reporting 1001,
        Application Hang 1002, .NET Runtime 1026) as flat records: executable name and path,
        faulting module, exception code.

    .DESCRIPTION
        The first step towards the sharing-violation proof: the events name the EXECUTABLES that
        fail. The data-file path being fought over only shows up in the ProcMon capture.

        Event 1000 carries a stable property layout; for everything else (and other locales) the
        rendered message is parsed, which also fills anything the properties left blank.

    .PARAMETER ComputerName
        Hosts to read. The local machine is read directly; a remote one through the Remote Event
        Log service (RPC), which needs that firewall rule and rights on the host.

    .PARAMETER Days
        How far back to look. Default 14.

    .PARAMETER AdditionalProvider
        Extra Application-log providers to include (an app's own crash source); every event ID
        from them is read.

    .EXAMPLE
        Get-NSPMDECrashEvent -Days 30

    .EXAMPLE
        Get-NSPMDECrashEvent -ComputerName APP01 | Get-NSPMDECandidateApp
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = @($env:COMPUTERNAME),
        [ValidateRange(1, 3650)][int]$Days = 14,
        [string[]]$AdditionalProvider = @()
    )

    $start = (Get-Date).AddDays(-$Days)
    $queries = @(@{ LogName = 'Application'; ProviderName = @('Application Error', 'Application Hang', 'Windows Error Reporting', '.NET Runtime'); Id = @(1000, 1001, 1002, 1026); StartTime = $start })
    if ($AdditionalProvider) { $queries += @{ LogName = 'Application'; ProviderName = @($AdditionalProvider); StartTime = $start } }

    foreach ($pc in $ComputerName) {
        $isLocal = (-not $pc) -or $pc -in @('.', 'localhost', $env:COMPUTERNAME)
        foreach ($query in $queries) {
            $read = @{ FilterHashtable = $query; ErrorAction = 'Stop' }
            if (-not $isLocal) { $read['ComputerName'] = $pc }
            $events = @()
            try { $events = @(Get-WinEvent @read) }
            catch {
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { continue }
                Write-Warning "Could not read the Application log on ${pc}: $($_.Exception.Message)"
                continue
            }

            foreach ($e in $events) {
                $msg = [string]$e.Message
                $props = @($e.Properties | ForEach-Object { $_.Value })
                $exeName = $null; $exePath = $null; $modPath = $null; $exCode = $null

                if ($e.Id -eq 1000) {
                    $exeName = $props[0]
                    if ($props.Count -gt 10) { $exePath = $props[10] }
                    if ($props.Count -gt 3) { $modPath = $props[3] }
                    if ($props.Count -gt 6) { $exCode = $props[6] }
                } elseif ($e.Id -eq 1002) {
                    $exeName = $props[0]
                }

                if ($msg) {
                    if ($msg -match 'Faulting application name:\s*([^,\r\n]+)') { $exeName = $Matches[1].Trim() }
                    if ($msg -match 'Faulting application path:\s*([^\r\n]+)') { $exePath = $Matches[1].Trim() }
                    if ($msg -match 'Faulting module path:\s*([^\r\n]+)') { $modPath = $Matches[1].Trim() }
                    if ($msg -match 'Exception code:\s*(0x[0-9A-Fa-f]+)') { $exCode = $Matches[1].Trim() }
                    if (-not $exeName -and $msg -match 'P1:\s*([^\r\n\s]+\.exe)') { $exeName = $Matches[1].Trim() }
                    if (-not $exeName -and $msg -match 'Application:\s*([^\r\n\s]+\.exe)') { $exeName = $Matches[1].Trim() }
                }
                if (-not $exeName) { continue }
                if ($exCode -is [int] -or $exCode -is [uint32] -or $exCode -is [long]) { $exCode = '0x{0:x8}' -f [uint32]([long]$exCode -band 0xFFFFFFFF) }

                [pscustomobject][ordered]@{
                    PSTypeName    = 'NSP.MDE.CrashEvent'
                    Computer      = $pc
                    TimeCreated   = $e.TimeCreated
                    EventId       = $e.Id
                    Provider      = $e.ProviderName
                    ExeName       = [string]$exeName
                    ExePath       = [string]$exePath
                    ModulePath    = [string]$modPath
                    ExceptionCode = [string]$exCode
                    Message       = ($msg -replace '\s+', ' ').Trim()
                }
            }
        }
    }
}
