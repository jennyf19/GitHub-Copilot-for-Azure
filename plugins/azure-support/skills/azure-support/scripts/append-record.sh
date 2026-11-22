#!/usr/bin/env bash
# append-record.sh
# Appends one entry to an azure-support session record. Secrets are redacted
# at write time, and each entry header carries a UTC timestamp and the SHA-256
# of the record content before the entry (a simple hash chain). At session end,
# --close appends a closing line with the SHA-256 of the whole record so far,
# which also covers the final entry. --verify checks the chain and the closing line.
#
# Usage:
#   ./append-record.sh --record <path> --entry-file <path> [--allow-workspace]
#   ./append-record.sh --record <path> --close [--allow-workspace]
#   ./append-record.sh --record <path> --verify
#
#   --allow-workspace  Permit a record inside a git work tree (only when the user
#                      explicitly asked); the record's folder is added to .gitignore.
#
# Exit codes: 0 = success / record intact, 1 = failure / record altered, 2 = invalid arguments.

set -euo pipefail

RECORD=""
ENTRY=""
MODE="append"
ALLOW_WS=0
MARKER="<!-- azure-support-entry"
CLOSE_MARKER="<!-- azure-support-close"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --record) RECORD="${2:-}"; shift 2 ;;
        --entry-file) ENTRY="${2:-}"; shift 2 ;;
        --verify) MODE="verify"; shift ;;
        --close) MODE="close"; shift ;;
        --allow-workspace) ALLOW_WS=1; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$RECORD" ]] || { echo "Usage: $0 --record <path> (--entry-file <path> | --close | --verify)" >&2; exit 2; }

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }

if [[ "$MODE" == "verify" ]]; then
    [[ -f "$RECORD" ]] || { echo "Record not found: $RECORD" >&2; exit 1; }
    status=0
    while IFS=: read -r offset line; do
        expected="$(sed -n 's/.*prev-sha256: \([0-9a-f]*\).*/\1/p' <<<"$line")"
        actual="$(head -c "$offset" "$RECORD" | sha)"
        if [[ "$expected" != "$actual" ]]; then
            echo "BROKEN entry at byte $offset: expected $expected, actual $actual"; status=1
        fi
    done < <(grep -b -- "^$MARKER" "$RECORD" || true)
    closes="$(grep -c -- "^$CLOSE_MARKER" "$RECORD" || true)"
    if [[ "$closes" -gt 1 ]]; then
        echo "BROKEN: more than one closing line"; status=1
    elif [[ "$closes" -eq 1 ]]; then
        IFS=: read -r offset line < <(grep -b -- "^$CLOSE_MARKER" "$RECORD")
        expected="$(sed -n 's/.*file-sha256: \([0-9a-f]*\).*/\1/p' <<<"$line")"
        actual="$(head -c "$offset" "$RECORD" | sha)"
        size="$(wc -c < "$RECORD" | tr -d ' ')"
        if [[ "$expected" != "$actual" ]]; then
            echo "BROKEN closing line: expected $expected, actual $actual"; status=1
        fi
        if [[ "$size" -ne $((offset + ${#line} + 1)) ]]; then
            echo "BROKEN: content after the closing line"; status=1
        fi
        [[ "$status" -eq 0 ]] && echo "INTACT: hash chain and closing line verified (record closed)."
    else
        [[ "$status" -eq 0 ]] && echo "INTACT: hash chain verified (record still open; final entry not yet sealed)."
    fi
    exit "$status"
fi

dir="$(dirname "$RECORD")"
mkdir -p "$dir"
chmod 700 "$dir" 2>/dev/null || true

if top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)"; then
    if [[ "$ALLOW_WS" -ne 1 ]]; then
        echo "Refusing to write inside a git work tree ($top). Use the local state directory, or pass --allow-workspace if the user explicitly asked." >&2
        exit 1
    fi
    rel="$(git -C "$dir" rev-parse --show-prefix)"
    [[ -n "$rel" ]] || rel="/$(basename "$RECORD")"
    touch "$top/.gitignore"
    grep -qxF -- "$rel" "$top/.gitignore" || printf '%s\n' "$rel" >> "$top/.gitignore"
fi

touch "$RECORD"
chmod 600 "$RECORD" 2>/dev/null || true
if grep -q -- "^$CLOSE_MARKER" "$RECORD"; then
    echo "Record is closed; start a new session record." >&2
    exit 1
fi
prev="$(sha < "$RECORD")"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$MODE" == "close" ]]; then
    printf '%s ts: %s | file-sha256: %s -->\n' "$CLOSE_MARKER" "$ts" "$prev" >> "$RECORD"
    echo "Closed $RECORD at $ts"
    exit 0
fi

[[ -n "$ENTRY" && -f "$ENTRY" ]] || { echo "Entry file not found: $ENTRY" >&2; exit 2; }

redacted="$(perl -0pe '
    s/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/<redacted-private-key>/gs;
    s/\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|client_secret|ClientSecret|secret|api[_-]?key|access[_-]?key|token)(\s*[:=]\s*)"?[^;"\s,]+"?/$1$2<redacted>/gi;
    s/([?&]sig=)[^&\s"]+/$1<redacted>/gi;
    s/\b(Bearer\s+)[A-Za-z0-9\-_.~+\/]+=*/$1<redacted>/gi;
    s/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/<redacted-token>/g;
    s/[A-Za-z0-9+\/]{30,}={1,2}/<redacted-key>/g;
    s/^<!-- azure-support-/<!-- (quoted) azure-support-/mg;
' "$ENTRY")"

printf '%s ts: %s | prev-sha256: %s -->\n%s\n\n' "$MARKER" "$ts" "$prev" "$redacted" >> "$RECORD"
echo "Appended entry at $ts to $RECORD"
