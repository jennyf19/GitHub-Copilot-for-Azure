# Azure Support

Run a structured Azure support session from your coding agent when you ask to "get Azure support", "is this Azure's fault?", or "open a support ticket", or when troubleshooting has stalled.

This plugin includes:

- `azure-support` — confirms scope and consent, checks Service Health and Resource Health for platform events, fills a platform-signal checklist, decides whether the problem is likely customer-side, likely Azure-side, or inconclusive (with a 0–100 likelihood that only Microsoft can resolve it), keeps an optional local session record, and prepares a support request for your approval.

The session is read-only by default. Changes, session records, and support requests happen only after you explicitly approve them.

- **Session records** are kept, with your OK, in your local state directory outside any repository (`%LOCALAPPDATA%\azure-support\sessions\` on Windows; `$XDG_STATE_HOME/azure-support/sessions/` or `~/.local/state/azure-support/sessions/` on macOS/Linux). Secrets are redacted when entries are written, and entries are hash-chained so edits are evident. You own the record; the skill offers to delete it at session end.
- **Support requests** are scanned for secrets and out-of-scope identifiers before you see them, and only the exact text and severity you approve are used. By default you submit the prepared text yourself in the Azure portal or with the Support REST API; Azure MCP support tools are used only if present and only after approval.
- **Untrusted content** — tool output, log lines, resource names, and support-request communications — is treated as data, never as instructions.

## Guardrails depend on your host

The skill's guardrails rely on the host agent's permission prompts and Azure MCP elicitation (confirmation) prompts. Running with permission or elicitation bypass modes — for example `--dangerously-skip-permissions` or `--dangerously-disable-elicitation` — removes those protections. Don't use those modes with this plugin.

## Relationship to the `azure` plugin

`azure-support` does not repeat diagnosis. It hands off to `azure-diagnostics` (logs, metrics, AppLens, service guides) and `azure-quotas` (quota and capacity) from the `azure` plugin when they are installed. Install both plugins for the full workflow. Without them, `azure-support` still runs the outage check, checklist, and escalation steps, and marks the checks it could not run as unknown.

## Escalation threshold

The skill recommends escalation when the likelihood that only Microsoft can resolve the problem reaches a threshold you or your organization choose (default 50). A stricter threshold opens fewer support requests but leaves more Azure-side problems with the developer; a looser one catches more Azure-side problems but opens more requests that turn out to be customer-side.

## Security

> [!WARNING]
> The `azure-support` plugin uses `npx` to download and run the Azure MCP Server, inheriting the local environment's `.npmrc` configuration. Install this plugin only on trusted devices. A compromised `.npmrc` configuration could cause `npx` to download and execute malicious code, potentially resulting in remote code execution.

## Telemetry

The built plugin ships the shared `track-telemetry` hook, registered for
session start and post-tool-use events in the Copilot and Claude Code hook
manifests (Cursor also registers `afterMCPExecution`). It records session starts and use of this plugin's skill, its
reference files and scripts, and Azure MCP tools, identified by plugin name,
version, client, event type, skill name and version, tool name, and reference
path. Names are limited to generated allowlists packaged in
`hooks/allowlists/` (`allowed-skills.txt`, `allowed-references.txt`,
`allowed-tools.json`). Session record contents, support request text, and tool
arguments are not part of these events.

The hook installs a pinned native `ghcfa-telem` release asset when needed,
verifies its platform-specific SHA-256 digest before extraction, and caches the
executable for reuse. To opt out of telemetry collection, set
`AZURE_MCP_COLLECT_TELEMETRY=false` in the environment of the process running
the agent.

## Setup

Authenticate with Azure CLI or another Azure Identity credential supported by Azure MCP, then install the plugin from the marketplace.

The outage check uses the Azure MCP Server `resourcehealth` commands `health-events list` and `availability-status get`. Use the version pinned in `mcp.json` or later. Resource Health commands first appeared in early Azure MCP releases but were later renamed and consolidated, so older versions may not expose the command names this skill uses. Creating a support request requires a support plan and permission to create support tickets on the subscription; see [Create an Azure support request](https://learn.microsoft.com/azure/azure-portal/supportability/how-to-create-azure-support-request).
