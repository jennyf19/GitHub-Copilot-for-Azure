<#
.SYNOPSIS
    Appends one entry to an azure-support session record, closes it, or verifies it.
.DESCRIPTION
    Secrets are redacted at write time. Each entry header carries a UTC timestamp and the
    SHA-256 of the record content before the entry (a simple hash chain). At session end,
    -Close appends a closing line with the SHA-256 of the whole record so far, which also
    covers the final entry. -Verify checks the chain and the closing line. Refuses to write
    inside a git work tree unless -AllowWorkspace is given (only when the user explicitly
    asked); then the record's folder is added to .gitignore.
.PARAMETER Record
    Path to the session record file.
.PARAMETER EntryFile
    Path to a file containing the entry text to append.
.PARAMETER Close
    Append the closing line. No entries can be appended afterwards.
.PARAMETER Verify
    Verify the hash chain and closing line instead of writing.
.PARAMETER AllowWorkspace
    Permit a record inside a git work tree.
.EXAMPLE
    .\append-record.ps1 -Record "$env:LOCALAPPDATA\azure-support\sessions\session-20260101T000000Z.md" -EntryFile entry.md
.NOTES
    Exit codes: 0 = success / record intact, 1 = failure / record altered, 2 = invalid arguments.
#>
param(
    [string]$Record,
    [string]$EntryFile,
    [switch]$Close,
    [switch]$Verify,
    [switch]$AllowWorkspace
)

$marker = '<!-- azure-support-entry'
$closeMarker = '<!-- azure-support-close'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-Sha256Hex([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

if (-not $Record) { Write-Error "Usage: append-record.ps1 -Record <path> (-EntryFile <path> | -Close | -Verify)"; exit 2 }

if ($Verify) {
    if (-not (Test-Path -LiteralPath $Record -PathType Leaf)) { Write-Error "Record not found: $Record"; exit 1 }
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Record))
    $text = $utf8.GetString($bytes)
    $status = 0
    foreach ($m in [regex]::Matches($text, "(?m)^$([regex]::Escape($marker)).*prev-sha256: ([0-9a-f]+)")) {
        $prefix = $utf8.GetBytes($text.Substring(0, $m.Index))
        $actual = Get-Sha256Hex $prefix
        if ($actual -ne $m.Groups[1].Value) {
            Write-Output "BROKEN entry at byte $($prefix.Length): expected $($m.Groups[1].Value), actual $actual"; $status = 1
        }
    }
    $closes = [regex]::Matches($text, "(?m)^$([regex]::Escape($closeMarker)).*file-sha256: ([0-9a-f]+) -->\n?")
    if ($closes.Count -gt 1) {
        Write-Output "BROKEN: more than one closing line"; $status = 1
    } elseif ($closes.Count -eq 1) {
        $c = $closes[0]
        $actual = Get-Sha256Hex ($utf8.GetBytes($text.Substring(0, $c.Index)))
        if ($actual -ne $c.Groups[1].Value) { Write-Output "BROKEN closing line: expected $($c.Groups[1].Value), actual $actual"; $status = 1 }
        if ($c.Index + $c.Length -ne $text.Length) { Write-Output "BROKEN: content after the closing line"; $status = 1 }
        if ($status -eq 0) { Write-Output "INTACT: hash chain and closing line verified (record closed)." }
    } elseif ($status -eq 0) {
        Write-Output "INTACT: hash chain verified (record still open; final entry not yet sealed)."
    }
    exit $status
}

$recordPath = [IO.Path]::GetFullPath($Record)
$dir = Split-Path -Parent $recordPath
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$top = & git -C $dir rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -eq 0 -and $top) {
    if (-not $AllowWorkspace) {
        Write-Error "Refusing to write inside a git work tree ($top). Use the local state directory, or pass -AllowWorkspace if the user explicitly asked."
        exit 1
    }
    $rel = (& git -C $dir rev-parse --show-prefix) -join ''
    if (-not $rel) { $rel = '/' + [IO.Path]::GetFileName($recordPath) }
    $gitignore = Join-Path $top '.gitignore'
    $existing = if (Test-Path -LiteralPath $gitignore) { Get-Content -LiteralPath $gitignore } else { @() }
    if ($existing -notcontains $rel) { [IO.File]::AppendAllText($gitignore, "$rel`n", $utf8) }
}

if (-not (Test-Path -LiteralPath $recordPath)) { [IO.File]::WriteAllBytes($recordPath, [byte[]]@()) }
$current = [IO.File]::ReadAllBytes($recordPath)
if ($utf8.GetString($current) -match "(?m)^$([regex]::Escape($closeMarker))") {
    Write-Error "Record is closed; start a new session record."
    exit 1
}
$prev = Get-Sha256Hex $current
$ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

if ($Close) {
    [IO.File]::AppendAllText($recordPath, "$closeMarker ts: $ts | file-sha256: $prev -->`n", $utf8)
    Write-Output "Closed $recordPath at $ts"
    exit 0
}

if (-not $EntryFile -or -not (Test-Path -LiteralPath $EntryFile -PathType Leaf)) { Write-Error "Entry file not found: $EntryFile"; exit 2 }

$entry = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $EntryFile)) -replace "`r`n", "`n"
$entry = [regex]::Replace($entry, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '<redacted-private-key>')
$entry = [regex]::Replace($entry, '(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|client_secret|ClientSecret|secret|api[_-]?key|access[_-]?key|token)(\s*[:=]\s*)"?[^;"\s,]+"?', '$1$2<redacted>')
$entry = [regex]::Replace($entry, '(?i)([?&]sig=)[^&\s"]+', '$1<redacted>')
$entry = [regex]::Replace($entry, '(?i)\b(Bearer\s+)[A-Za-z0-9\-_.~+/]+=*', '$1<redacted>')
$entry = [regex]::Replace($entry, '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*', '<redacted-token>')
$entry = [regex]::Replace($entry, '[A-Za-z0-9+/]{30,}={1,2}', '<redacted-key>')
$entry = [regex]::Replace($entry, '(?m)^<!-- azure-support-', '<!-- (quoted) azure-support-')

[IO.File]::AppendAllText($recordPath, "$marker ts: $ts | prev-sha256: $prev -->`n$($entry.TrimEnd("`n"))`n`n", $utf8)
Write-Output "Appended entry at $ts to $recordPath"
exit 0
