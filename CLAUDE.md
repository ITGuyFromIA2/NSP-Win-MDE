# CLAUDE.md

## What this is

`NSP.Win.MDE`: evidence that Defender for Endpoint's EDR sensor (MsSense.exe) causes an app's
file sharing violations, for an EDR (Sense) exclusion request. Part of the `NSP.Win.*` family and a
tool in NSP.Toolkit's launcher (`MDE`). Sibling modules (Bootstrap, Console, Toolkit) load through
`Private\Import-NSPToolkitModule.ps1` - a generated copy of NSP-Toolkit's canonical loader (don't
edit it here). Why it works this way: `docs\Design.md`.

## Hard rules

- Windows PowerShell 5.1 is the floor; imports on a bare host (no RequiredModules). Only the menu
  (`Start-NSPMDETroubleshooter`, `Private\MenuHandlers.ps1`) needs the sibling modules.
- Nothing client-specific in tracked files. The field handoff under `docs\` names a client and is
  git-ignored; tests and examples use `APP01`, `LobApp.exe`, `Example Co`.
- Every ProcMon binary passes `Test-NSPProcmonSignature` (valid, Microsoft) before it runs - the
  tool is elevated and some search folders are user-writable.
- `.pmc` bytes come from `ConvertTo-NSPProcmonConfigBytes` only; `Tests\Fixtures\*.pmc` are the
  reference and must stay byte-identical. Never combine a Result include with a Process Name
  include in one filter (see Design.md).
- Filters never drop events; the analysis re-filters the capture itself.
- Tests never run ProcMon, download, or read real Defender state: mock `Invoke-NSPProcmonExe`,
  `Test-NSPProcmonSignature`, `Invoke-WebRequest`, `Get-WinEvent`, `Get-Mp*`, `Get-CimInstance`.
- Don't use `@($list)` on a `New-Object Collections.Generic.List[...]` - pwsh 7.6 throws
  "Argument types do not match"; use `.ToArray()`.
- One function per file in `Public\`. `FunctionsToExport` matches `Public\`. Exported functions
  need `.SYNOPSIS` and `.EXAMPLE`. CRLF, no BOM, ASCII only. Small (patch-level) version bumps.

## Testing

Pester 5+. Run `.\tools\Test-Repo.ps1` (PSScriptAnalyzer, then Pester under 5.1 and pwsh).

## Publishing

`tools\Publish-ToGallery.ps1` runs `Publish-NSPModule` from NSP.RepoTools. Dry run first with
`-WhatIf`. At release, change the CHANGELOG heading from `## <version> (unreleased)` to
`## <version>`. Needs a GitHub remote first (the manifest's ProjectUri points at it).
