#!/usr/bin/env bash
# scan-ticket.sh
# Deterministic secret and out-of-scope identifier scan for a composed Azure
# support request (or any text file) before it is shown to the user for approval.
# Also flags unpadded high-entropy tokens (32+ chars of [A-Za-z0-9+/_-] with Shannon
# entropy above 4.5 bits/char) that are not plain words or in-scope IDs.
# Prints each finding with line number and rule, with the matched value masked.
#
# Usage:
#   ./scan-ticket.sh --file <ticket.md> [--scope <id>]...
#
#   --scope  An in-scope subscription ID, resource ID, or GUID. Repeatable.
#            GUIDs and resource IDs in the text that are not covered by a
#            --scope value are reported as out of scope.
#
# Exit codes: 0 = clean, 1 = findings (stop and ask the user to edit), 2 = invalid arguments.

set -euo pipefail

FILE=""
SCOPES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) FILE="${2:-}"; shift 2 ;;
        --scope) SCOPES+=("${2:-}"); shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "Usage: $0 --file <ticket.md> [--scope <id>]..." >&2
    exit 2
fi

SCOPE_LIST="$(printf '%s\n' "${SCOPES[@]+"${SCOPES[@]}"}" | tr '[:upper:]' '[:lower:]')"
export SCOPE_LIST

perl -ne '
    BEGIN {
        @rules = (
            ["private-key",       qr/-----BEGIN [A-Z ]*PRIVATE KEY-----/],
            ["connection-string", qr/(?:AccountKey|SharedAccessKey|SharedAccessSignature|DefaultEndpointsProtocol|Endpoint=sb:\/\/)[^\s;]*/i],
            ["sas-token",         qr/[?&]sig=[^&\s"]+/i],
            ["bearer-token",      qr/\bBearer\s+[A-Za-z0-9\-_.~+\/]+=*/i],
            ["jwt",               qr/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/],
            ["password-or-secret",qr/\b(?:password|passwd|pwd|client_secret|clientsecret|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+/i],
            ["base64-key",        qr/[A-Za-z0-9+\/]{30,}={1,2}/],
        );
        @scopes = grep { length } split /\n/, ($ENV{SCOPE_LIST} // "");
        $hits = 0;
    }
    sub mask { my $v = shift; return length($v) <= 8 ? "****" : substr($v, 0, 4) . "****"; }
    sub in_scope {
        my $v = lc shift;
        for my $s (@scopes) { return 1 if index($v, $s) >= 0 || index($s, $v) >= 0; }
        return 0;
    }
    for my $r (@rules) {
        while (/$r->[1]/g) { $hits++; print "line $.: [$r->[0]] " . mask($&) . "\n"; }
    }
    while (/[A-Za-z0-9+\/_-]{32,}/g) {
        my $tok = $&;
        next if $tok =~ /subscriptions\//i || $tok =~ /^[A-Za-z]+$/ || in_scope($tok);
        my %freq; $freq{$_}++ for split //, $tok;
        my $h = 0; my $n = length $tok;
        for my $c (values %freq) { my $p = $c / $n; $h -= $p * log($p) / log(2); }
        next unless $h > 4.5;
        $hits++; print "line $.: [high-entropy] " . mask($tok) . sprintf(" (%.2f bits/char)\n", $h);
    }
    while (/\/subscriptions\/[^\s"`)]+/gi) {
        next if in_scope($&);
        $hits++; print "line $.: [out-of-scope-resource] $&\n";
    }
    while (/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi) {
        next if in_scope($&);
        $hits++; print "line $.: [out-of-scope-guid] $&\n";
    }
    END {
        if ($hits) { print "FINDINGS: $hits. Do not submit. Show these to the user and ask them to edit the text.\n"; exit 1; }
        print "CLEAN: no secrets or out-of-scope identifiers found.\n"; exit 0;
    }
' "$FILE"
