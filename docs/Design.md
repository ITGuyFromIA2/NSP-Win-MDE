# Design notes - MsSense sharing-violation evidence

Why the module works the way it does. The original field handoff (with client details) is kept
locally under `docs\` and is git-ignored; this is the same material without them.

## The failure being proved

Seen first with an accounting app writing client files on a file share (2026), and the same
pattern behind earlier cases with other line-of-business apps:

1. The app writes a file and closes it.
2. About 0.5 ms later it reopens the same file **exclusively** (`Desired Access: Generic
   Read/Write`, `ShareMode: None`) to rewrite it.
3. In between, **MsSense.exe** - the Defender for Endpoint **EDR sensor**, not the antivirus
   engine - opened the just-written file to inspect it (`ShareMode: Read, Write, Delete`) and still
   holds that handle.
4. The exclusive reopen fails with `STATUS_SHARING_VIOLATION (0xC0000043)`; the app errors or
   crashes. MsSense closes its handle ~1 ms later.

In the original capture every app failure (5 of 5) showed this signature. MsMpEng.exe (the
antivirus engine) also touched the file, but was not the holder at the moment of the violation.

**Consequence:** an antivirus exclusion, or turning real-time protection off, does not help. The
sensor needs a Defender for Endpoint **EDR (Sense) exclusion** - a capability Microsoft grants
through a support case (private preview), and the case needs this proof.

## Pipeline

```
crash/hang events -> candidate executables -> ProcMon capture -> collisions + verdict -> JSON
 (Application log)    (name, path, count)      (user reproduces)  (who held the file)
```

Crash events only name the executables. The data-file path being fought over (often a UNC share)
only appears in the capture - so the folders are optional input, and the analysis offers the
contested folders back for the activity filter.

## ProcMon filters (.pmc)

The binary `.pmc` format was first produced with the Python `procmon-parser` library. The module
writes it natively (`ConvertTo-NSPProcmonConfigBytes`); the tests require byte-identical output
against the Python-generated files in `Tests\Fixtures`. Layout: one record (`UInt32` record size,
header size 0x10, data offset, data size; UTF-16 name `FilterRules`), then `Byte 1`, `Byte` rule
count, 3 zero bytes, and per rule `UInt32` column, `UInt32` relation, `Byte` action, `UInt32` value
byte length, UTF-16 value with NUL, `UInt64 0`.

ProcMon's filter semantics shape the profiles: include rules within one column are OR'd; an event
must match an include in EVERY column that has includes. So `Result is SHARING VIOLATION` and a
`Process Name` include must not share a filter - together they hide the sensor's successful open.
Hence separate profiles: Violations, Activity (opens/closes on data-folder fragments), Processes
(app + MsSense + MsMpEng opens/closes), and FileOpens (what the analysis exports).

Filters never drop events (the module doesn't set "Drop Filtered Events"): the backing file keeps
everything, so the analysis can re-filter it.

## Analysis

`Find-NSPMDECollision` walks the exported opens and closes in order, tracking which process holds
which path. ProcMon's CSV has no handle values, so one process's overlapping opens of one path pair
with its closes oldest-first - fine for this signature, where the holder opens once. At each
violation, the other processes' open handles on that path are the holders:

| HolderKind | Meaning | Request |
|---|---|---|
| EDR | MsSense.exe / Sense*.exe held it | EDR (Sense) exclusion - the case this module exists for |
| AV | MsMpEng.exe / MpDefenderCoreService.exe / NisSrv.exe | Ordinary antivirus exclusion |
| Other | Another process (backup, indexer, another app instance) | Not Defender |
| NotSeen | Holder opened it before the capture started | Capture again, starting earlier |

## Verified live (ProcMon 4.11, Windows 11, MDE onboarded, 2026-10-15)

- **FilterRules-only `.pmc` files work.** `/LoadConfig` at capture time, and `/SaveApplyFilter`
  exports honour the generated filters exactly (an export with the FileOpens filter held only
  CreateFile/CloseFile).
- **Holder detection.** A forced exclusive reopen against a file held by another process was
  reported with the right holder and hold time. MsSense.exe was seen live in the opposite role:
  refused when reading files a test process held with `ShareMode: None` (48 times in one minute).
  That is harmless to the app, so `ProcessKind` keeps it out of the evidence (`DefenderRefused`).
- **Size and speed.** One minute on a busy workstation: a 2.2 GB `.pml`, 5.4 M events. Exporting
  every open and close (448 k rows, 102 MB CSV) then reading it took about 4 minutes, so the export is two
  stages: violations first, then opens/closes of only those files - 16 seconds end to end, same result.
- **Incomplete captures.** Twice in seven runs ProcMon wrote a backing file whose index held only
  its first second (hundreds of MB on disk, ~1 s readable) - both right after another ProcMon
  instance had exited. Nothing in ProcMon reports it, and it reads as "no violations".
  `Stop-NSPProcmonCapture` measures coverage from thread-exit events and flags it (`Incomplete`).

## Still to verify

- Remote crash-event harvest (`Get-NSPMDECrashEvent -ComputerName`) needs the Remote Event Log
  firewall rule and rights on the target.
- A real MsSense-held collision through the module (the case evidence in the field handoff was
  analysed by hand in ProcMon).
