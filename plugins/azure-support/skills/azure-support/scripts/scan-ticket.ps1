<#
.SYNOPSIS
    Deterministic secret and out-of-scope identifier scan for a composed Azure support request.
.DESCRIPTION
    Scans a text file (the composed support request) before it is shown to the user for
    approval. Prints each finding with line number and rule, with the matched value masked.
    GUIDs and resource IDs not covered by a -Scope value are reported as out of scope.
.PARAMETER File
    Path to the composed support request text.
.PARAMETER Scope
    In-scope subscription IDs, resource IDs, or GUIDs.
.EXAMPLE
    .\scan-ticket.ps1 -File ticket.md -Scope /subscriptions/<id>/resourceGroups/my-rg
.NOTES
    Exit codes: 0 = clean, 1 = findings (stop and ask the user to edit), 2 = invalid arguments.
#>
param(
    [string]$File,
    [string[]]$Scope = @()
)

if (-not $File -or -not (Test-Path -LiteralPath $File -PathType Leaf)) {
    Write-Error "Usage: scan-ticket.ps1 -File <ticket.md> [-Scope <id>[,<id>...]]"
    exit 2
}

$rules = [ordered]@{
    'private-key'        = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'connection-string'  = '(?i)(?:AccountKey|SharedAccessKey|SharedAccessSignature|DefaultEndpointsProtocol|Endpoint=sb://)[^\s;]*'
    'sas-token'          = '(?i)[?&]sig=[^&\s"]+'
    'bearer-token'       = '(?i)\bBearer\s+[A-Za-z0-9\-_.~+/]+=*'
    'jwt'                = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
    'password-or-secret' = '(?i)\b(?:password|passwd|pwd|client_secret|clientsecret|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+'
    'base64-key'         = '[A-Za-z0-9+/]{30,}={1,2}'
}
$scopes = $Scope | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }

function Get-Mask([string]$v) { if ($v.Length -le 8) { '****' } else { $v.Substring(0, 4) + '****' } }
function Test-InScope([string]$v) {
    $v = $v.ToLowerInvariant()
    foreach ($s in $scopes) { if ($v.Contains($s) -or $s.Contains($v)) { return $true } }
    return $false
}

$hits = 0
$lineNo = 0
foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $File))) {
    $lineNo++
    foreach ($name in $rules.Keys) {
        foreach ($m in [regex]::Matches($line, $rules[$name])) {
            $hits++; Write-Output "line ${lineNo}: [$name] $(Get-Mask $m.Value)"
        }
    }
    foreach ($m in [regex]::Matches($line, '(?i)/subscriptions/[^\s"`)]+')) {
        if (-not (Test-InScope $m.Value)) { $hits++; Write-Output "line ${lineNo}: [out-of-scope-resource] $($m.Value)" }
    }
    foreach ($m in [regex]::Matches($line, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')) {
        if (-not (Test-InScope $m.Value)) { $hits++; Write-Output "line ${lineNo}: [out-of-scope-guid] $($m.Value)" }
    }
}

if ($hits -gt 0) {
    Write-Output "FINDINGS: $hits. Do not submit. Show these to the user and ask them to edit the text."
    exit 1
}
Write-Output "CLEAN: no secrets or out-of-scope identifiers found."
exit 0
