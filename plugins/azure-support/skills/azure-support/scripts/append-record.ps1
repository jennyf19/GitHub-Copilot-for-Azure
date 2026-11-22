<#
.SYNOPSIS
    Appends one entry to an azure-support session record, or verifies its hash chain.
.DESCRIPTION
    Secrets are redacted at write time. Each entry header carries a UTC timestamp and the
    SHA-256 of the record content before the entry (a simple hash chain), so later edits are
    detectable with -Verify. Refuses to write inside a git work tree unless -AllowWorkspace
    is given (only when the user explicitly asked); then the record's folder is added to
    .gitignore.
.PARAMETER Record
    Path to the session record file.
.PARAMETER EntryFile
    Path to a file containing the entry text to append.
.PARAMETER Verify
    Verify the hash chain instead of appending.
.PARAMETER AllowWorkspace
    Permit a record inside a git work tree.
.EXAMPLE
    .\append-record.ps1 -Record "$env:LOCALAPPDATA\azure-support\sessions\session-20260101T000000Z.md" -EntryFile entry.md
.NOTES
    Exit codes: 0 = success / chain intact, 1 = failure / chain broken, 2 = invalid arguments.
#>
param(
    [string]$Record,
    [string]$EntryFile,
    [switch]$Verify,
    [switch]$AllowWorkspace
)

$marker = '<!-- azure-support-entry'
$utf8 = [Text.UTF8Encoding]::new($false)

function Get-Sha256Hex([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

if (-not $Record) { Write-Error "Usage: append-record.ps1 -Record <path> (-EntryFile <path> | -Verify)"; exit 2 }

if ($Verify) {
    if (-not (Test-Path -LiteralPath $Record -PathType Leaf)) { Write-Error "Record not found: $Record"; exit 1 }
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Record))
    $text = $utf8.GetString($bytes)
    $status = 0
    foreach ($m in [regex]::Matches($text, "(?m)^$([regex]::Escape($marker)).*prev-sha256: ([0-9a-f]+)")) {
        $prefix = $utf8.GetBytes($text.Substring(0, $m.Index))
        $actual = Get-Sha256Hex $prefix
        if ($actual -ne $m.Groups[1].Value) {
            Write-Output "BROKEN at byte $($prefix.Length): expected $($m.Groups[1].Value), actual $actual"; $status = 1
        }
    }
    if ($status -eq 0) { Write-Output "INTACT: hash chain verified." }
    exit $status
}

if (-not $EntryFile -or -not (Test-Path -LiteralPath $EntryFile -PathType Leaf)) { Write-Error "Entry file not found: $EntryFile"; exit 2 }

$dir = Split-Path -Parent ([IO.Path]::GetFullPath($Record))
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$top = & git -C $dir rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -eq 0 -and $top) {
    if (-not $AllowWorkspace) {
        Write-Error "Refusing to write inside a git work tree ($top). Use the local state directory, or pass -AllowWorkspace if the user explicitly asked."
        exit 1
    }
    $topFull = [IO.Path]::GetFullPath($top)
    $rel = [IO.Path]::GetRelativePath($topFull, $dir).Replace('\', '/') + '/'
    if ($rel -eq './') { $rel = '/' + [IO.Path]::GetFileName($Record) }
    $gitignore = Join-Path $topFull '.gitignore'
    $existing = if (Test-Path -LiteralPath $gitignore) { Get-Content -LiteralPath $gitignore } else { @() }
    if ($existing -notcontains $rel) { [IO.File]::AppendAllText($gitignore, "$rel`n", $utf8) }
}

$recordPath = [IO.Path]::GetFullPath($Record)
if (-not (Test-Path -LiteralPath $recordPath)) { [IO.File]::WriteAllBytes($recordPath, [byte[]]@()) }
$prev = Get-Sha256Hex ([IO.File]::ReadAllBytes($recordPath))
$ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

$entry = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $EntryFile)) -replace "`r`n", "`n"
$entry = [regex]::Replace($entry, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '<redacted-private-key>')
$entry = [regex]::Replace($entry, '(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|client_secret|ClientSecret|secret|api[_-]?key|access[_-]?key|token)(\s*[:=]\s*)"?[^;"\s,]+"?', '$1$2<redacted>')
$entry = [regex]::Replace($entry, '(?i)([?&]sig=)[^&\s"]+', '$1<redacted>')
$entry = [regex]::Replace($entry, '(?i)\b(Bearer\s+)[A-Za-z0-9\-_.~+/]+=*', '$1<redacted>')
$entry = [regex]::Replace($entry, '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*', '<redacted-token>')
$entry = [regex]::Replace($entry, '[A-Za-z0-9+/]{30,}={1,2}', '<redacted-key>')

[IO.File]::AppendAllText($recordPath, "$marker ts: $ts | prev-sha256: $prev -->`n$($entry.TrimEnd("`n"))`n`n", $utf8)
Write-Output "Appended entry at $ts to $recordPath"
exit 0
