# Session Record

Keep a session record only with the user's OK. Write it **outside any repository or workspace** by default.

## Location

| OS | Default directory |
|----|-------------------|
| Windows | `%LOCALAPPDATA%\azure-support\sessions\` |
| macOS / Linux | `$XDG_STATE_HOME/azure-support/sessions/`, or `~/.local/state/azure-support/sessions/` if `XDG_STATE_HOME` is unset |

File name: `session-<UTC timestamp, e.g. 20260101T120000Z>.md`.

Write into the workspace only if the user explicitly asks. Then pass `-AllowWorkspace` / `--allow-workspace`; the script adds the record's folder to the repository's `.gitignore`.

## Writing entries

Append every entry with the bundled script. Never edit the record file directly.

```powershell
.\scripts\append-record.ps1 -Record <record-path> -EntryFile <entry.md>
.\scripts\append-record.ps1 -Record <record-path> -Verify
```
```bash
./scripts/append-record.sh --record <record-path> --entry-file <entry.md>
./scripts/append-record.sh --record <record-path> --verify
```

- **Redaction at write time.** The script replaces keys, connection-string secrets, SAS signatures, bearer tokens, JWTs, passwords, private keys, and long base64 keys with `<redacted…>` before writing. Still leave secrets out of entries you compose; the script is a safety net.
- **Hash chain.** Each entry header holds a UTC timestamp and the SHA-256 of the record content before the entry. `--verify` / `-Verify` reports any entry whose preceding content changed. This makes accidental or casual edits evident; it is not a signature.
- Write the entry file in the same private directory and delete it after appending.

## Entries to write

1. **Scope** — subscription, resource IDs, region(s), consent given (read-only / approved changes).
2. **Symptom** — user's description (no secrets), exact error code, onset, last known good, customer changes.
3. **Check** (one per check) — check name, tool or skill used, result, including `unknown` / unestablished states and why.
4. **Checklist result** — always written before any decision: every field from [checklist.md](checklist.md) with its value and evidence, plus `top_customer_side_cause`, `needs_microsoft`, `p_microsoft` (0–100), the threshold in use, the decision (likely customer-side / likely Azure-side / inconclusive), and `why`.
5. **Hypotheses** — each with evidence for and against.
6. **Action** — proposed, approved (yes/no), taken, verification result.
7. **Support request** — final approved text (after the scan passed), severity, submission path, returned reference.
8. **Outcome** — `resolved-verified`, `resolved-unverified`, `escalated`, or `inconclusive`.

## Retention and cleanup

The record stays on the user's machine; the user owns it and deletes it. At session end, tell the user where the record is and offer to delete it. Delete only with the user's yes.
