# Changelog

All notable changes to NSP.Win.MDE are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## 0.1.0 (unreleased)

First release: the MsSense sharing-violation evidence tooling as a module.

- `Start-NSPMDETroubleshooter`: self-elevating menu (status, crash events, filters, capture,
  analysis, ProcMon view, hand-back). Registered in NSP.Toolkit as tool `MDE`.
- ProcMon `.pmc` filters written natively - no Python - byte-identical to the procmon-parser
  output they replace.
- `Find-NSPMDECollision`: names the holder of each sharing violation (EDR / AV / Other / NotSeen)
  and the hand-back states the verdict.
- ProcMon is found or downloaded, and must be Microsoft-signed before it runs.
- Capture folder (menu F) and capture files are picked with Windows pickers (`Read-NSPFolderPath` /
  `Read-NSPFilePath`); needs NSP.Console 0.1.5.

The other NSP modules it needs are installed from the PowerShell Gallery the first time they're needed,
so `Install-Module` of this one module is enough. Set `NSP_NO_AUTOINSTALL=1` to turn that off.
