# Process Monitor plumbing: the .pmc filter-file format, the signature check every ProcMon binary
# passes before it runs elevated, the runner, and CSV time parsing.

# ---------------------------------------------------------------------------
# .pmc format. Decoded from configuration files generated (and round-tripped) with the Python
# procmon-parser library - Tests\Fixtures\*.pmc are those files, and the writer below must
# reproduce them byte for byte.
#
#   record   UInt32 RecordSize  (header + name + data)
#            UInt32 HeaderSize  (always 0x10)
#            UInt32 DataOffset  (0x10 + name bytes)
#            UInt32 DataSize
#            name   UTF-16LE, NUL-terminated ("FilterRules")
#            data
#   FilterRules data
#            Byte   1 (constant)
#            Byte   rule count
#            Byte[3] 0
#            rules  UInt32 Column, UInt32 Relation, Byte Action (1 include, 0 exclude),
#                   UInt32 value bytes, value UTF-16LE NUL-terminated, UInt64 0
#
# ProcMon reads a file holding only FilterRules and keeps its other settings (columns, highlight).
# Filters are display-only unless "Drop Filtered Events" is on, which this module never sets: the
# backing file always holds every event, so the analysis can re-filter it.

$script:NSPProcmonColumn = @{
    ProcessName = 40053   # 0x9C75
    PID         = 40054
    Operation   = 40055   # 0x9C77
    Result      = 40056   # 0x9C78
    Detail      = 40057
    ImagePath   = 40068
    Path        = 40071   # 0x9C87
    Duration    = 40077
}

$script:NSPProcmonRelation = @{
    Is = 0; IsNot = 1; LessThan = 2; MoreThan = 3; BeginsWith = 4; EndsWith = 5; Contains = 6; Excludes = 7
}

function ConvertTo-NSPProcmonConfigBytes {
    # The .pmc bytes for a list of rules (objects with Column, Relation, Value, Action).
    param([Parameter(Mandatory)][object[]]$Rule)

    if ($Rule.Count -gt 255) { throw 'A ProcMon filter holds at most 255 rules.' }
    $unicode = [Text.Encoding]::Unicode
    $data = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter($data)
    try {
        $w.Write([byte]1)
        $w.Write([byte]$Rule.Count)
        $w.Write([byte[]](0, 0, 0))
        foreach ($r in $Rule) {
            if (-not $script:NSPProcmonColumn.ContainsKey([string]$r.Column)) { throw "Unknown ProcMon column '$($r.Column)'." }
            if (-not $script:NSPProcmonRelation.ContainsKey([string]$r.Relation)) { throw "Unknown ProcMon relation '$($r.Relation)'." }
            $value = $unicode.GetBytes([string]$r.Value + [char]0)
            $w.Write([uint32]$script:NSPProcmonColumn[[string]$r.Column])
            $w.Write([uint32]$script:NSPProcmonRelation[[string]$r.Relation])
            $w.Write([byte]$(if ($r.Action -eq 'Exclude') { 0 } else { 1 }))
            $w.Write([uint32]$value.Length)
            $w.Write($value)
            $w.Write([uint64]0)
        }
        $w.Flush()
        [byte[]]$body = $data.ToArray()
    } finally { $w.Dispose() }

    $name = $unicode.GetBytes('FilterRules' + [char]0)
    $out = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter($out)
    try {
        $w.Write([uint32](0x10 + $name.Length + $body.Length))
        $w.Write([uint32]0x10)
        $w.Write([uint32](0x10 + $name.Length))
        $w.Write([uint32]$body.Length)
        $w.Write($name)
        $w.Write($body)
        $w.Flush()
        , $out.ToArray()
    } finally { $w.Dispose() }
}

function ConvertFrom-NSPProcmonConfigBytes {
    # Reads the FilterRules record back (tests, and the menu's "what's in this filter" view).
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $columns = @{}; foreach ($k in $script:NSPProcmonColumn.Keys) { $columns[$script:NSPProcmonColumn[$k]] = $k }
    $relations = @{}; foreach ($k in $script:NSPProcmonRelation.Keys) { $relations[$script:NSPProcmonRelation[$k]] = $k }
    $r = New-Object IO.BinaryReader((New-Object IO.MemoryStream(, $Bytes)))
    try {
        while ($r.BaseStream.Position -lt $r.BaseStream.Length) {
            $start = $r.BaseStream.Position
            $size = $r.ReadUInt32(); $null = $r.ReadUInt32(); $offset = $r.ReadUInt32(); $null = $r.ReadUInt32()
            $name = [Text.Encoding]::Unicode.GetString($r.ReadBytes($offset - 0x10)).TrimEnd([char]0)
            if ($name -ne 'FilterRules') { $r.BaseStream.Position = $start + $size; continue }
            $null = $r.ReadByte()
            $count = $r.ReadByte()
            $null = $r.ReadBytes(3)
            for ($i = 0; $i -lt $count; $i++) {
                $column = $r.ReadUInt32(); $relation = $r.ReadUInt32(); $action = $r.ReadByte()
                $value = [Text.Encoding]::Unicode.GetString($r.ReadBytes($r.ReadUInt32())).TrimEnd([char]0)
                $null = $r.ReadUInt64()
                [pscustomobject]@{
                    Column   = if ($columns.ContainsKey([int]$column)) { $columns[[int]$column] } else { "$column" }
                    Relation = if ($relations.ContainsKey([int]$relation)) { $relations[[int]$relation] } else { "$relation" }
                    Value    = $value
                    Action   = if ($action) { 'Include' } else { 'Exclude' }
                }
            }
            $r.BaseStream.Position = $start + $size
        }
    } finally { $r.Dispose() }
}

# ---------------------------------------------------------------------------
function Test-NSPProcmonSignature {
    # True when the file carries a valid Authenticode signature from Microsoft. Every ProcMon
    # binary is checked before it runs: the troubleshooter runs elevated, and some of the folders
    # searched (ProgramData, the script folder) can be written by ordinary users.
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $sig -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $false }
    return ($sig.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)')
}

function Invoke-NSPProcmonExe {
    # Runs ProcMon with the given arguments. -Wait blocks until it exits (conversions, /Terminate);
    # without it the process object is returned (a capture).
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList, [switch]$Wait)
    $quoted = foreach ($arg in $ArgumentList) { if ($arg -match '[\s"]') { '"' + ($arg -replace '"', '\"') + '"' } else { $arg } }
    Write-Verbose "$FilePath $(@($quoted) -join ' ')"
    $start = @{ FilePath = $FilePath; ArgumentList = @($quoted); PassThru = $true }
    if ($Wait) { $start['Wait'] = $true }
    Start-Process @start
}

function Export-NSPProcmonCsv {
    # One ProcMon export of a .pml to CSV with a filter applied.
    param([Parameter(Mandatory)][string]$ProcmonPath, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$FilterPath, [Parameter(Mandatory)][string]$CsvPath)
    Write-Verbose "Exporting $Path to $CsvPath"
    $null = Invoke-NSPProcmonExe -FilePath $ProcmonPath -Wait -ArgumentList @('/AcceptEula', '/Quiet', '/Minimized', '/OpenLog', $Path, '/LoadConfig', $FilterPath, '/SaveApplyFilter', '/SaveAs', $CsvPath)
    if (-not (Test-Path -LiteralPath $CsvPath)) { throw "ProcMon did not write $CsvPath." }
}

function Get-NSPProcmonCoverage {
    # How many seconds a .pml actually covers: the first and last thread exit in it (they happen
    # system-wide every second, and are few enough to export quickly). ProcMon intermittently
    # writes a backing file whose index holds only its first second, and nothing else shows it -
    # seen right after another ProcMon instance exited. $null when it can't be measured.
    param([Parameter(Mandatory)][string]$ProcmonPath, [Parameter(Mandatory)][string]$Path)
    $temp = Join-Path ([IO.Path]::GetTempPath()) ("NSP_{0}" -f [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $temp -Force
    try {
        $pmc = Join-Path $temp 'coverage.pmc'
        [IO.File]::WriteAllBytes($pmc, (ConvertTo-NSPProcmonConfigBytes -Rule ([pscustomobject]@{ Column = 'Operation'; Relation = 'Is'; Value = 'Thread Exit'; Action = 'Include' })))
        $csv = Join-Path $temp 'coverage.csv'
        Export-NSPProcmonCsv -ProcmonPath $ProcmonPath -Path $Path -FilterPath $pmc -CsvPath $csv
        $rows = @(Import-Csv -LiteralPath $csv)
        if (-not $rows) { return $null }
        $first = ConvertFrom-NSPProcmonTimeOfDay $rows[0].'Time of Day'
        $last = ConvertFrom-NSPProcmonTimeOfDay $rows[-1].'Time of Day'
        if ($null -eq $first -or $null -eq $last) { return $null }
        $span = $last - $first
        if ($span -lt [TimeSpan]::Zero) { $span += [TimeSpan]::FromDays(1) }   # across midnight
        [Math]::Round($span.TotalSeconds, 1)
    } catch {
        Write-Verbose "Coverage not measured: $($_.Exception.Message)"
        return $null
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-NSPProcmonToolFolder {
    # Where Save-NSPProcmon puts ProcMon: the MDE work folder (Administrators and SYSTEM only) when
    # NSP.Toolkit is loaded, otherwise %ProgramData%\NSP\Tools.
    if (Get-Command Get-NSPToolWorkPath -ErrorAction SilentlyContinue) { return (Join-Path (Get-NSPToolWorkPath -Tool MDE) 'Tools') }
    return (Join-Path $env:ProgramData 'NSP\Tools')
}

# ---------------------------------------------------------------------------
function ConvertFrom-NSPProcmonTimeOfDay {
    # ProcMon's "Time of Day" column ("4:05:12.1234567 PM", or 24-hour "16:05:12.1234567") as a
    # TimeSpan with 100 ns precision; $null when it doesn't parse. Culture-independent on purpose.
    param([AllowEmptyString()][string]$Text)
    if ($Text -notmatch '^\s*(?<h>\d{1,2}):(?<m>\d{2}):(?<s>\d{2})(?:[.,](?<f>\d{1,7}))?\s*(?<ampm>[AaPp]\.?[Mm]\.?)?\s*$') { return $null }
    $h = [int]$Matches.h; $m = [int]$Matches.m; $s = [int]$Matches.s
    $fraction = [string]$Matches.f; $ampm = [string]$Matches.ampm
    if ($ampm) {
        if ($h -eq 12) { $h = 0 }
        if ($ampm.StartsWith('P', [StringComparison]::OrdinalIgnoreCase)) { $h += 12 }
    }
    $ticks = if ($fraction) { [long]($fraction.PadRight(7, '0')) } else { 0L }
    New-Object TimeSpan(([long]$h * 3600 + $m * 60 + $s) * 10000000L + $ticks)
}

function Get-NSPProcmonDetailField {
    # One "Name: value" field from ProcMon's Detail column (e.g. ShareMode, Desired Access).
    param([AllowEmptyString()][string]$Detail, [Parameter(Mandatory)][string]$Name)
    if ($Detail -match ('(?:^|,\s*)' + [regex]::Escape($Name) + ':\s*(?<v>[^,]*)')) { return $Matches.v.Trim() }
    return ''
}

function Get-NSPFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '') } finally { $stream.Dispose(); $sha.Dispose() }
}
