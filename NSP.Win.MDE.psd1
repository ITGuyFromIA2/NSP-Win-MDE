@{
    RootModule = 'NSP.Win.MDE.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'daea30b5-247f-4cc0-8ee8-fddd149f92af'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) 2026 Network Systems Plus. All rights reserved.'
    Description = 'Microsoft Defender for Endpoint troubleshooting: prove a file sharing-violation collision between the EDR sensor (MsSense.exe) and a line-of-business app, for a Defender for Endpoint EDR exclusion request. Crash/hang event harvest, Process Monitor filter files written natively, capture, automated collision analysis, and a JSON hand-back. Windows PowerShell 5.1 compatible.'

    # 5.1 is the floor for every NSP toolkit, and the module must import on a bare 5.1 host -
    # sibling NSP modules are loaded on first use (Private\Import-NSPToolkitModule.ps1), never
    # declared as RequiredModules.
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'ConvertFrom-NSPProcmonLog'
        'Export-NSPMDEResponse'
        'Find-NSPMDECollision'
        'Find-NSPProcmon'
        'Get-NSPMDECandidateApp'
        'Get-NSPMDECrashEvent'
        'Get-NSPMDEStatus'
        'New-NSPProcmonFilter'
        'Save-NSPProcmon'
        'Start-NSPMDETroubleshooter'
        'Start-NSPProcmonCapture'
        'Stop-NSPProcmonCapture'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('NSP', 'Defender', 'MDE', 'EDR', 'MsSense', 'Procmon', 'Sysinternals', 'Troubleshooting', 'Windows')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-Win-MDE'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-Win-MDE/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/ITGuyFromIA2/NSP-Win-MDE/blob/main/CHANGELOG.md'
        }
    }
}
