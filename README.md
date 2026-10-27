# NSP.Win.MDE

Microsoft Defender for Endpoint troubleshooting: prove that the EDR sensor (**MsSense.exe**) causes
a line-of-business app's file **sharing violations**, for a Defender for Endpoint **EDR exclusion**
request. Windows PowerShell **5.1** compatible (and 7+); imports on a bare host.

```powershell
Install-Module NSP.Win.MDE; Start-NSPMDETroubleshooter      # or: Start-NSPToolkit -Tool MDE
```

Run it on the machine where the app fails. It relaunches elevated, then:

1. **Defender for Endpoint status** - sensor version and onboarding, AV mode, tamper protection, exclusions.
2. **Crash and hang events** - the executables that fail (Application Error 1000, WER 1001, Hang 1002, .NET 1026).
3. **ProcMon filters** - app executables and data-folder fragments; three `.pmc` files written natively.
4. **Start capture** - ProcMon runs minimized; the user reproduces the failure.
5. **Stop capture and analyze** - every SHARING VIOLATION, and who held the file: MsSense (EDR), MsMpEng (AV), other.
6. **Analyze an existing capture** - a `.pml` or ProcMon `.csv` from earlier.
7. **Open the capture in ProcMon** - with a filter loaded, for screenshots in the support case.
8. **Write the hand-back JSON** - `<Company>_MDE_Response.json` (NSP.Toolkit Response hand-off).

ProcMon is a GUI program and can't run inside the console; the capture runs minimized and the
console does the rest. If ProcMon isn't on the machine the tool offers to download it from
live.sysinternals.com. Every ProcMon binary - found or downloaded - must carry a valid Microsoft
signature before it runs.

Why an antivirus exclusion doesn't fix this, and how the proof works: [docs/Design.md](docs/Design.md).

## Functions

| Function | Purpose |
|---|---|
| `Start-NSPMDETroubleshooter` | The menu. |
| `Get-NSPMDEStatus` | Sensor and antivirus facts (no elevation needed; exclusions only show elevated). |
| `Get-NSPMDECrashEvent` / `Get-NSPMDECandidateApp` | Crash/hang events, local or `-ComputerName`, and the executables behind them. |
| `Find-NSPProcmon` / `Save-NSPProcmon` | Find a Microsoft-signed ProcMon, or download one. |
| `New-NSPProcmonFilter` | Write a `.pmc` filter: Violations, Activity, Processes, FileOpens, Custom. |
| `Start-NSPProcmonCapture` / `Stop-NSPProcmonCapture` | Background capture to a `.pml`. |
| `ConvertFrom-NSPProcmonLog` | A `.pml` (exported through ProcMon) or `.csv` as events. |
| `Find-NSPMDECollision` | Each sharing violation and its holder (EDR / AV / Other / NotSeen). |
| `Export-NSPMDEResponse` | The hand-back JSON. |

Without the menu:

```powershell
$pm = Find-NSPProcmon; if (-not $pm) { $pm = Save-NSPProcmon }
$c = Start-NSPProcmonCapture -ProcmonPath $pm -OutputDirectory D:\Captures -RuntimeSeconds 300
# ... reproduce the failure ...
$c = $c | Stop-NSPProcmonCapture
$hits = ConvertFrom-NSPProcmonLog -Path $c.BackingFile -ProcmonPath $pm | Find-NSPMDECollision
Export-NSPMDEResponse -Company 'Example Co' -ApplicationName 'Example App' -Capture $c -Collision $hits
```

## Where things go

Captures, filters and crash-event CSVs: `%ProgramData%\NSP\Toolkit\MDE\Captures` (or
`-OutputRoot`). Hand-back: `%ProgramData%\NSP\Toolkit\MDE\Responses`. Downloaded ProcMon:
`%ProgramData%\NSP\Toolkit\MDE\Tools`. The Toolkit folder is limited to Administrators and SYSTEM.

## Tests

```powershell
.\tools\Test-Repo.ps1      # PSScriptAnalyzer + Pester 5 under Windows PowerShell 5.1 and pwsh
```
