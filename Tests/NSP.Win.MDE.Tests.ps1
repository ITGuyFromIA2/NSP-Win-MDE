<#
    Pester 5. Nothing here runs ProcMon, downloads anything, or reads the real Defender state:
    the ProcMon runner (Invoke-NSPProcmonExe), the signature check, Invoke-WebRequest, Get-WinEvent
    and the Defender/CIM/registry reads are mocked. Tests\Fixtures\*.pmc are filter files generated
    with the Python procmon-parser library; the native writer must reproduce them byte for byte.
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.Win.MDE.psd1') -Force -ErrorAction Stop
    $script:Fixtures = Join-Path $PSScriptRoot 'Fixtures'
    function Get-TestBase64([string]$Path) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) }
    # Defender cmdlets are absent on some hosts; Pester can only mock a command that exists.
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { function global:Get-MpComputerStatus { } }
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { function global:Get-MpPreference { } }
}

Describe 'New-NSPProcmonFilter' {
    It 'writes the violations filter byte for byte' {
        $f = New-NSPProcmonFilter -Kind Violations -OutputPath (Join-Path $TestDrive 'v.pmc')
        Get-TestBase64 $f.FullName | Should -BeExactly (Get-TestBase64 (Join-Path $Fixtures 'NSP_SharingViolations.pmc'))
    }
    It 'writes the share-activity filter byte for byte' {
        $f = New-NSPProcmonFilter -Kind Activity -Path '\Clients\', '\Paperless\' -OutputPath (Join-Path $TestDrive 'a.pmc')
        Get-TestBase64 $f.FullName | Should -BeExactly (Get-TestBase64 (Join-Path $Fixtures 'NSP_ShareFileActivity.pmc'))
    }
    It 'writes the app-and-Defender filter byte for byte, adding MsSense and MsMpEng' {
        $f = New-NSPProcmonFilter -Kind Processes -ProcessName 'DrakeAccounting2026.exe', 'pvxwin64.exe' -OutputPath (Join-Path $TestDrive 'p.pmc')
        Get-TestBase64 $f.FullName | Should -BeExactly (Get-TestBase64 (Join-Path $Fixtures 'NSP_AppAndEdr.pmc'))
    }
    It 'reads back what it wrote, excludes included' {
        $rules = @(
            [pscustomobject]@{ Column = 'Path'; Relation = 'BeginsWith'; Value = 'D:\Data\'; Action = 'Include' }
            [pscustomobject]@{ Column = 'ProcessName'; Relation = 'Is'; Value = 'Explorer.EXE'; Action = 'Exclude' }
        )
        $f = New-NSPProcmonFilter -Kind Custom -Rule $rules -OutputPath (Join-Path $TestDrive 'c.pmc')
        $back = @(InModuleScope NSP.Win.MDE -Parameters @{ P = $f.FullName } { param($P) ConvertFrom-NSPProcmonConfigBytes -Bytes ([IO.File]::ReadAllBytes($P)) })
        ($back | ForEach-Object { "$($_.Column)|$($_.Relation)|$($_.Value)|$($_.Action)" }) | Should -Be @('Path|BeginsWith|D:\Data\|Include', 'ProcessName|Is|Explorer.EXE|Exclude')
    }
    It 'needs a path fragment for Activity' {
        { New-NSPProcmonFilter -Kind Activity -OutputPath (Join-Path $TestDrive 'x.pmc') } | Should -Throw '*-Path*'
    }
    It 'refuses an unknown column' {
        { New-NSPProcmonFilter -Kind Custom -Rule ([pscustomobject]@{ Column = 'Nope'; Relation = 'Is'; Value = 'x' }) -OutputPath (Join-Path $TestDrive 'x.pmc') } | Should -Throw '*column*'
    }
}

Describe 'ProcMon time of day' {
    It 'parses <Text>' -ForEach @(
        @{ Text = '2:15:30.1004500 PM'; Ticks = ((14 * 3600 + 15 * 60 + 30) * 10000000L + 1004500) }
        @{ Text = '12:00:00.5 AM'; Ticks = 5000000L }
        @{ Text = '12:00:01.0000000 PM'; Ticks = (12 * 3600 + 1) * 10000000L }
        @{ Text = '23:59:59.0000001'; Ticks = (86399 * 10000000L + 1) }
    ) {
        (InModuleScope NSP.Win.MDE -Parameters @{ T = $Text } { param($T) ConvertFrom-NSPProcmonTimeOfDay $T }).Ticks | Should -Be $Ticks
    }
    It 'returns nothing for text it does not know' {
        InModuleScope NSP.Win.MDE { ConvertFrom-NSPProcmonTimeOfDay 'yesterday' } | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-NSPProcmonLog and Find-NSPMDECollision' {
    BeforeAll {
        $script:events = @(ConvertFrom-NSPProcmonLog -Path (Join-Path $Fixtures 'Collision.csv'))
        $script:collisions = @($events | Find-NSPMDECollision)
    }
    It 'reads every row with its time' {
        $events.Count | Should -Be 17
        $events[0].TimeOfDay | Should -BeOfType [TimeSpan]
    }
    It 'finds the four sharing violations' {
        $collisions.Count | Should -Be 4
    }
    It 'marks Defender as the refused process when it cannot read a file the app holds exclusively' {
        $collisions[3].ProcessName | Should -Be 'MsSense.exe'
        $collisions[3].ProcessKind | Should -Be 'EDR'
        $collisions[3].HolderKind | Should -Be 'Other'
        $collisions[3].Holders[0].ProcessName | Should -Be 'LobApp.exe'
        $collisions[0].ProcessKind | Should -Be 'Other'
    }
    It 'names MsSense.exe as the holder of the exclusive reopen (the proven signature)' {
        $c = $collisions[0]
        $c.HolderKind | Should -Be 'EDR'
        $c.ProcessName | Should -Be 'LobApp.exe'
        $c.ShareMode | Should -Be 'None'
        $c.DesiredAccess | Should -Be 'Generic Read/Write'
        @($c.Holders).Count | Should -Be 1 -Because 'MsMpEng opened and closed before the reopen'
        $c.Holders[0].ProcessName | Should -Be 'MsSense.exe'
        $c.Holders[0].ShareMode | Should -Be 'Read'
        $c.Holders[0].HeldMs | Should -Be 1.8 -Because 'opened at .1004500, closed at .1022500'
    }
    It 'names MsMpEng.exe when the antivirus engine holds the file' {
        $collisions[1].HolderKind | Should -Be 'AV'
        $collisions[1].Holders[0].ProcessName | Should -Be 'MsMpEng.exe'
    }
    It 'says NotSeen when the holder opened the file before the capture' {
        $collisions[2].HolderKind | Should -Be 'NotSeen'
        @($collisions[2].Holders).Count | Should -Be 0
    }
    It 'refuses a CSV without ProcMon''s default columns' {
        $bad = Join-Path $TestDrive 'bad.csv'
        Set-Content -LiteralPath $bad -Value '"Time of Day","Process Name","Operation"', '"1:00:00 PM","a.exe","CreateFile"'
        { ConvertFrom-NSPProcmonLog -Path $bad } | Should -Throw '*PID*'
    }
    It 'needs ProcMon to export a .pml' {
        $pml = Join-Path $TestDrive 'c.pml'; Set-Content -LiteralPath $pml -Value 'x'
        { ConvertFrom-NSPProcmonLog -Path $pml } | Should -Throw '*-ProcmonPath*'
    }
    It 'exports the violations, then only the opens and closes of the files that had one' {
        $pml = Join-Path $TestDrive 'e.pml'; Set-Content -LiteralPath $pml -Value 'x'
        $script:filters = @{}
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $true }
        Mock -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe {
            $out = $ArgumentList[$ArgumentList.IndexOf('/SaveAs') + 1]
            $pmc = $ArgumentList[$ArgumentList.IndexOf('/LoadConfig') + 1]
            $script:filters[(Split-Path -Leaf $out)] = [IO.File]::ReadAllBytes($pmc)
            $rows = @(Import-Csv (Join-Path $Fixtures 'Collision.csv'))
            if ($out -like '*.violations.csv') { $rows = @($rows | Where-Object Result -eq 'SHARING VIOLATION') }
            $rows | Export-Csv -LiteralPath $out -NoTypeInformation
        }
        @(ConvertFrom-NSPProcmonLog -Path $pml -ProcmonPath 'C:\x\Procmon64.exe').Count | Should -Be 17
        Should -Invoke -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe -Times 2 -Exactly -ParameterFilter {
            ($ArgumentList -join ' ') -match '^/AcceptEula /Quiet /Minimized /OpenLog .*e\.pml /LoadConfig .*\.pmc /SaveApplyFilter /SaveAs .*e\.(violations\.)?csv$' -and $Wait
        }
        $decode = { param([byte[]]$B) @(InModuleScope NSP.Win.MDE -Parameters @{ B = $B } { param($B) ConvertFrom-NSPProcmonConfigBytes -Bytes $B }) }
        @(& $decode $filters['e.violations.csv'] | ForEach-Object { "$($_.Column) $($_.Value)" }) | Should -Be @('Result SHARING VIOLATION')
        $second = @(& $decode $filters['e.csv'])
        @($second | Where-Object Column -eq 'Operation' | ForEach-Object Value) | Should -Be @('CreateFile', 'CloseFile')
        @($second | Where-Object Column -eq 'Path' | ForEach-Object { "$($_.Relation) $($_.Value)" } | Sort-Object) | Should -Be @(
            'Is C:\ProgramData\Lob\lock.dat', 'Is \\APP01\apps\Lob\Data\Clients\1001\ClientFileEF', 'Is \\APP01\apps\Lob\Data\Clients\1001\Index.dat', 'Is \\APP01\apps\Lob\Data\Paperless\scan.pdf' | Sort-Object)
    }
    It 'yields no events when the capture had no violations' {
        $pml = Join-Path $TestDrive 'none.pml'; Set-Content -LiteralPath $pml -Value 'x'
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $true }
        Mock -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe {
            Set-Content -LiteralPath $ArgumentList[$ArgumentList.IndexOf('/SaveAs') + 1] -Value '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"'
        }
        @(ConvertFrom-NSPProcmonLog -Path $pml -ProcmonPath 'C:\x\Procmon64.exe').Count | Should -Be 0
        Should -Invoke -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe -Times 1 -Exactly
    }
}

Describe 'Evidence summary and payload' {
    BeforeAll {
        $script:collisions = @(ConvertFrom-NSPProcmonLog -Path (Join-Path $Fixtures 'Collision.csv') | Find-NSPMDECollision)
        $script:candidate = [pscustomobject]@{ ExeName = 'LobApp.exe'; Hits = 3; ExePaths = @('C:\Program Files\Lob\LobApp.exe'); FirstSeen = [datetime]'2026-10-01'; LastSeen = [datetime]'2026-10-14'; ExceptionCodes = @('0xc0000005'); EventIds = @(1000) }
    }
    It 'counts holders and says an EDR exclusion is needed when MsSense held the file' {
        $s = InModuleScope NSP.Win.MDE -Parameters @{ C = $collisions } { param($C) Get-NSPMDEEvidenceSummary -Collision $C }
        $s.Violations | Should -Be 3
        $s.HeldByEdr | Should -Be 1
        $s.HeldByAv | Should -Be 1
        $s.HolderNotSeen | Should -Be 1
        $s.DefenderRefused | Should -Be 1 -Because 'MsSense being refused is not evidence'
        $s.Verdict | Should -BeLike '*EDR (Sense) exclusion is required*'
    }
    It 'does not claim an EDR case when only the antivirus engine held files' {
        $av = @($collisions | Where-Object HolderKind -eq 'AV')
        (InModuleScope NSP.Win.MDE -Parameters @{ C = $av } { param($C) Get-NSPMDEEvidenceSummary -Collision $C }).Verdict | Should -BeLike '*antivirus exclusion should resolve it*'
    }
    It 'says to reproduce when nothing was captured' {
        (InModuleScope NSP.Win.MDE { Get-NSPMDEEvidenceSummary -Collision @() }).Verdict | Should -BeLike 'No sharing violations*'
    }
    It 'suggests the Defender-held folders and the app''s full path' {
        $p = InModuleScope NSP.Win.MDE -Parameters @{ C = $collisions; A = $candidate } { param($C, $A) New-NSPMDEResponsePayload -Company 'Example Co' -Collision $C -Candidate $A }
        $p.SuggestedExclusion.Folders | Should -Be @('\\APP01\apps\Lob\Data\Clients\1001\', '\\APP01\apps\Lob\Data\Paperless\')
        $p.SuggestedExclusion.Processes | Should -Be @('C:\Program Files\Lob\LobApp.exe')
        $p.Evidence.ContestedPaths.Count | Should -Be 3
        $p.Application.Candidates[0].FirstSeen | Should -Be '2026-10-01T00:00:00'
    }
    It 'survives JSON with the holders intact' {
        $p = InModuleScope NSP.Win.MDE -Parameters @{ C = $collisions } { param($C) New-NSPMDEResponsePayload -Company 'Example Co' -Collision $C -MaxCollisions 2 }
        $back = ConvertTo-Json -InputObject $p -Depth 20 | ConvertFrom-Json
        $back.Evidence.Violations | Should -Be 3
        @($back.Evidence.Collisions).Count | Should -Be 2
        $back.Evidence.Collisions[0].Holders[0].ProcessName | Should -Be 'MsSense.exe'
    }
}

Describe 'Export-NSPMDEResponse' {
    BeforeAll {
        $script:collisions = @(ConvertFrom-NSPProcmonLog -Path (Join-Path $Fixtures 'Collision.csv') | Find-NSPMDECollision)
        $script:status = [pscustomobject]@{ OperatingSystem = 'Windows Test'; MsSenseVersion = '10.0.0.1'; Onboarded = $true; AMRunningMode = 'Normal' }
    }
    It 'writes plain JSON without NSP.Toolkit' {
        Mock -ModuleName NSP.Win.MDE Get-Command { $null } -ParameterFilter { $Name -in 'New-NSPHandoff', 'Get-NSPToolWorkPath' }
        $f = Export-NSPMDEResponse -Company 'Example Co' -OutputDirectory $TestDrive -Status $status -Collision $collisions
        $f.Name | Should -Be 'ExampleCo_MDE_Response.json'
        $p = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
        $p.Tool | Should -Be 'NSP.Win.MDE'
        $p.Mde.MsSenseVersion | Should -Be '10.0.0.1'
        $p.Evidence.HeldByEdr | Should -Be 1
    }
    It 'writes an NSP.Toolkit Response hand-off when the toolkit is loaded' {
        $toolkit = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'NSP-Toolkit\NSP.Toolkit.psd1'
        if (-not (Test-Path -LiteralPath $toolkit)) { Set-ItResult -Skipped -Because 'NSP-Toolkit is not checked out next to this repository'; return }
        Import-Module $toolkit -Force
        $f = Export-NSPMDEResponse -Company 'Example Co' -OutputDirectory (Join-Path $TestDrive 'h') -Status $status -Collision $collisions
        $f.Name | Should -Be 'ExampleCo_MDE_Response.json'
        $h = Import-NSPHandoff -Path $f.FullName -Tool MDE -Kind Response
        $h.Payload.Evidence.Violations | Should -Be 3
    }
    It 'writes nothing with -WhatIf' {
        Export-NSPMDEResponse -Company 'Example Co' -OutputDirectory (Join-Path $TestDrive 'w') -Status $status -WhatIf
        Test-Path (Join-Path $TestDrive 'w\ExampleCo_MDE_Response.json') | Should -BeFalse
    }
}

Describe 'Crash events and candidates' {
    BeforeAll {
        function New-TestEvent($Id, $Provider, $Props, $Message, $When) {
            [pscustomobject]@{ Id = $Id; ProviderName = $Provider; TimeCreated = $When; Message = $Message; Properties = @($Props | ForEach-Object { [pscustomobject]@{ Value = $_ } }) }
        }
    }
    It 'reads 1000 properties, parses 1001 messages, and groups by executable' {
        $e1000 = New-TestEvent 1000 'Application Error' @('LobApp.exe', '1.0', '0', 'C:\Program Files\Lob\core.dll', '1.0', '0', [uint32]3221225477, '0', '0', '0', 'C:\Program Files\Lob\LobApp.exe') 'Faulting application name: LobApp.exe, version: 1.0' ([datetime]'2026-10-10')
        $e1001 = New-TestEvent 1001 'Windows Error Reporting' @() "Fault bucket , type 0`r`nEvent Name: APPCRASH`r`nP1: LobApp.exe`r`nP2: 1.0" ([datetime]'2026-10-12')
        $e1002 = New-TestEvent 1002 'Application Hang' @('Other.exe', '2.0') 'The program Other.exe stopped interacting with Windows.' ([datetime]'2026-10-11')
        Mock -ModuleName NSP.Win.MDE Get-WinEvent { $e1000; $e1001; $e1002 }
        $events = @(Get-NSPMDECrashEvent -Days 7)
        $events.Count | Should -Be 3
        $events[0].ExePath | Should -Be 'C:\Program Files\Lob\LobApp.exe'
        $events[0].ExceptionCode | Should -Be '0xc0000005'
        $events[1].ExeName | Should -Be 'LobApp.exe'
        Should -Invoke -ModuleName NSP.Win.MDE Get-WinEvent -ParameterFilter { -not $PSBoundParameters.ContainsKey('ComputerName') } -Because 'the local log is read without RPC'

        $c = @($events | Get-NSPMDECandidateApp)
        $c[0].ExeName | Should -Be 'LobApp.exe'
        $c[0].Hits | Should -Be 2
        $c[0].LastSeen | Should -Be ([datetime]'2026-10-12')
        @($events | Get-NSPMDECandidateApp -ProcessName 'Other.exe').ExeName | Should -Be 'Other.exe'
    }
    It 'treats "no events" as none, not an error' {
        Mock -ModuleName NSP.Win.MDE Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
        @(Get-NSPMDECrashEvent -WarningVariable w -WarningAction SilentlyContinue).Count | Should -Be 0
        $w | Should -BeNullOrEmpty
    }
    It 'reads a remote computer through -ComputerName' {
        Mock -ModuleName NSP.Win.MDE Get-WinEvent { }
        $remote = 'APP01'
        $null = Get-NSPMDECrashEvent -ComputerName $remote
        Should -Invoke -ModuleName NSP.Win.MDE Get-WinEvent -ParameterFilter { $ComputerName -eq 'APP01' }
    }
}

Describe 'Get-NSPMDEStatus' {
    It 'reports the sensor and hides exclusions it may not see' {
        Mock -ModuleName NSP.Win.MDE Get-CimInstance { [pscustomobject]@{ PathName = '"C:\NoSuch\Platform\Versions\10.8838.26060.15013-0\MsSense.exe"'; State = 'Running'; StartMode = 'Auto' } } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock -ModuleName NSP.Win.MDE Get-CimInstance { [pscustomobject]@{ Caption = 'Windows Test'; Version = '10.0.1' } } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock -ModuleName NSP.Win.MDE Get-ItemProperty { [pscustomobject]@{ OnboardingState = 1; OrgId = '00000000-0000-0000-0000-000000000001' } }
        Mock -ModuleName NSP.Win.MDE Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Normal'; IsTamperProtected = $true; AMProductVersion = '4.18' } }
        Mock -ModuleName NSP.Win.MDE Get-MpPreference { [pscustomobject]@{ ExclusionPath = @('N/A: Must be an administrator to view exclusions'); ExclusionProcess = @(); ExclusionExtension = @() } }
        $s = Get-NSPMDEStatus
        $s.MsSensePath | Should -Be 'C:\NoSuch\Platform\Versions\10.8838.26060.15013-0\MsSense.exe'
        $s.MsSenseVersion | Should -Be '10.8838.26060.15013' -Because 'the folder name stands in when the file cannot be read'
        $s.SenseState | Should -Be 'Running'
        $s.Onboarded | Should -BeTrue
        $s.AMRunningMode | Should -Be 'Normal'
        $s.ExclusionsVisible | Should -BeFalse
        @($s.ExclusionPath).Count | Should -Be 0
    }
}

Describe 'Finding and downloading ProcMon' {
    It 'skips a copy that is not signed by Microsoft' {
        $exe = Join-Path $TestDrive 'Procmon64.exe'; Set-Content -LiteralPath $exe -Value 'x'
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $false }
        Find-NSPProcmon -Path $exe -WarningVariable w -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        "$w" | Should -BeLike '*not validly signed*'
    }
    It 'returns a signed copy from a folder' {
        $dir = Join-Path $TestDrive 'pm'; New-Item -ItemType Directory -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'Procmon64.exe') -Value 'x'
        Set-Content -LiteralPath (Join-Path $dir 'Procmon.exe') -Value 'x'
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $Path -like "$TestDrive*" }
        $expected = if ([Environment]::Is64BitOperatingSystem) { 'Procmon64.exe' } else { 'Procmon.exe' }
        Split-Path -Leaf (Find-NSPProcmon -Path $dir) | Should -Be $expected
    }
    It 'deletes a download that fails the signature check' {
        Mock -ModuleName NSP.Win.MDE Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value 'fake' }
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $false }
        { Save-NSPProcmon -Destination (Join-Path $TestDrive 'dl') } | Should -Throw '*not validly signed*'
        @(Get-ChildItem (Join-Path $TestDrive 'dl')).Count | Should -Be 0
    }
    It 'keeps a signed download' {
        Mock -ModuleName NSP.Win.MDE Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value 'signed' }
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $true }
        $p = Save-NSPProcmon -Destination (Join-Path $TestDrive 'ok') -Uri 'https://live.sysinternals.com/Procmon64.exe'
        $p | Should -Be (Join-Path $TestDrive 'ok\Procmon64.exe')
        Test-Path -LiteralPath "$p.download" | Should -BeFalse
    }
    It 'only downloads over HTTPS' {
        { Save-NSPProcmon -Destination $TestDrive -Uri 'http://live.sysinternals.com/Procmon64.exe' } | Should -Throw '*HTTPS*'
    }
}

Describe 'Capture start and stop' {
    BeforeAll {
        $script:filter = (New-NSPProcmonFilter -Kind Violations -OutputPath (Join-Path $TestDrive 'v.pmc')).FullName
    }
    BeforeEach {
        Mock -ModuleName NSP.Win.MDE Test-NSPProcmonSignature { $true }
        Mock -ModuleName NSP.Win.MDE Get-Item { [pscustomobject]@{ VersionInfo = [pscustomobject]@{ ProductVersion = '4.01' } } } -ParameterFilter { $LiteralPath -like '*Procmon64.exe' }
    }
    It 'starts ProcMon quiet and minimized with the backing file, filter and run time' {
        Mock -ModuleName NSP.Win.MDE Get-Process { }
        Mock -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe { [pscustomobject]@{ Id = 4242 } }
        $c =Start-NSPProcmonCapture -ProcmonPath 'C:\Tools\Procmon64.exe' -OutputDirectory (Join-Path $TestDrive 'cap') -FilterPath $filter -RuntimeSeconds 300 -MinimumFreeGB 0
        $c.ProcessId | Should -Be 4242
        $c.BackingFile | Should -BeLike '*\cap\capture_*.pml'
        Should -Invoke -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe -Times 1 -Exactly -ParameterFilter {
            $a = $ArgumentList -join ' '
            $a -match '^/AcceptEula /Quiet /Minimized /BackingFile .*capture_\d{8}-\d{6}\.pml /LoadConfig .*v\.pmc /Runtime 300$' -and -not $Wait
        }
    }
    It 'refuses to start while ProcMon is already running' {
        Mock -ModuleName NSP.Win.MDE Get-Process { [pscustomobject]@{ Id = 1 } }
        Mock -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe { }
        { Start-NSPProcmonCapture -ProcmonPath 'C:\Tools\Procmon64.exe' -OutputDirectory $TestDrive } | Should -Throw '*already running*'
        Should -Invoke -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe -Times 0
    }
    It 'does not run /Terminate when ProcMon already stopped by itself' {
        Mock -ModuleName NSP.Win.MDE Get-Process { }
        Mock -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe { }
        Mock -ModuleName NSP.Win.MDE Get-NSPProcmonCoverage { 19.5 }
        $pml = Join-Path $TestDrive 'done.pml'; Set-Content -LiteralPath $pml -Value 'x'
        $c = [pscustomobject]@{ ProcmonPath = 'C:\Tools\Procmon64.exe'; BackingFile = $pml; Started = (Get-Date).AddSeconds(-24); Ended = $null }
        $c = $c | Stop-NSPProcmonCapture -TimeoutSeconds 2
        $c.Ended | Should -Not -BeNullOrEmpty
        $c.CoveredSeconds | Should -Be 19.5
        $c.Incomplete | Should -BeFalse
        Should -Invoke -ModuleName NSP.Win.MDE Invoke-NSPProcmonExe -Times 0
    }
    It 'flags a capture whose file covers only its first second' {
        Mock -ModuleName NSP.Win.MDE Get-Process { }
        Mock -ModuleName NSP.Win.MDE Get-NSPProcmonCoverage { 1.0 }
        $pml = Join-Path $TestDrive 'short.pml'; Set-Content -LiteralPath $pml -Value 'x'
        $c = [pscustomobject]@{ ProcmonPath = 'C:\Tools\Procmon64.exe'; BackingFile = $pml; Started = (Get-Date).AddSeconds(-40); Ended = $null }
        $c = $c | Stop-NSPProcmonCapture -TimeoutSeconds 2 -WarningVariable w -WarningAction SilentlyContinue
        $c.Incomplete | Should -BeTrue
        "$w" | Should -BeLike '*covers only 1 of the 40 seconds*'
    }
}

Describe 'Capture coverage' {
    It 'measures the span between the first and last thread exit, across midnight too' {
        Mock -ModuleName NSP.Win.MDE Export-NSPProcmonCsv {
            Set-Content -LiteralPath $CsvPath -Value '"Time of Day","Operation"', '"11:59:58.5000000 PM","Thread Exit"', '"12:00:10.0000000 AM","Thread Exit"'
        }
        InModuleScope NSP.Win.MDE { Get-NSPProcmonCoverage -ProcmonPath 'C:\x\Procmon64.exe' -Path 'C:\x\c.pml' } | Should -Be 11.5
        Should -Invoke -ModuleName NSP.Win.MDE Export-NSPProcmonCsv -Times 1 -Exactly
    }
}
