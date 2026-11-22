# Platform-Signal Checklist

Fill in this checklist from the evidence gathered in the session and give your own call on whether only Microsoft can resolve the problem. A good support engineer rules out the customer side before escalating; follow that discipline. Be literal: judge the case on its own evidence, not a template.

## Fields

```jsonc
{
  "facts": {
    "customer_change_before_onset": "yes" | "no" | "unknown",
    "onset": "sudden" | "gradual" | "always" | "unknown",
    "scope": "single_resource" | "many_resources" | "region_or_service_wide" | "unknown",
    "platform_event_reported": "yes" | "no",   // host/node reboot, live migration, storage/disk reset, maintenance, platform-initiated unavailability, service incident
    "capacity_or_quota_error": "yes" | "no",   // AllocationFailed, SkuNotAvailable, capacity, quota/limit increase needed
    "internal_service_error": "yes" | "no",    // Azure service/control plane returned an internal/5xx/unexpected server error
    "stuck_operation": "yes" | "no",           // resource/operation stuck in provisioning/updating/deleting/failed; retries didn't fix
    "customer_side_plausible": "yes" | "no",   // is there still a plausible customer-side cause (config, code, network, permissions, version, usage) that the evidence does NOT rule out?
    "customer_checks_done": "yes" | "no",      // has the customer already checked/ruled out the likely customer-side causes (e.g., verified config, reproduced on a clean setup, same code works elsewhere)?
    "top_customer_side_cause": "<= 15 words, or 'none'",
    "evidence": "<= 25 words behind any 'yes'"
  },
  "needs_microsoft": true | false,   // only Microsoft can resolve: platform bug, backend action, quota/capacity grant, outage
  "p_microsoft": 0-100,              // your probability (integer %) that only Microsoft can resolve it; use the full range, be calibrated, avoid clustering at 0/50/100
  "why": "<1 sentence>"
}
```

## Sources for each field

| Field | Where the evidence usually comes from |
|-------|---------------------------------------|
| `customer_change_before_onset` | User's account, Activity Log, deployment history |
| `onset`, `scope` | User's timeline, metrics, other resources in the region |
| `platform_event_reported` | Service Health events, Resource Health reason, platform-initiated annotations |
| `capacity_or_quota_error` | Deployment/operation error codes, `azure-quotas` findings |
| `internal_service_error` | Azure API/control-plane responses (not the app's own 5xx) |
| `stuck_operation` | Provisioning state, Activity Log operation status, retry results |
| `customer_side_plausible`, `customer_checks_done`, `top_customer_side_cause` | `azure-diagnostics` findings and the user's prior checks |

Record the checklist in the session record and show it to the user with the decision.
