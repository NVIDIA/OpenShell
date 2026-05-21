# OpenShell Policy Advisor

Use this when OpenShell blocks a network request and the response or logs say
`policy_denied`.

## Goal

Draft the smallest policy proposal that allows the user's current task without
giving the sandbox broad new network access. The developer approves or rejects
the proposal; do not try to bypass policy.

## Local API

The sandbox-local policy API is reachable at `http://policy.local`:

- `GET /v1/policy/current` — current effective policy as YAML.
- `GET /v1/denials?last=10` — most recent network/L7 denials seen by this
  sandbox (newest first), returned as raw shorthand log lines. Each line
  carries the timestamp, class, severity, action, host/port, binary, policy
  name, and (for denied events) a short reason. Read the lines directly; you
  do not need to parse them into structured fields.
- `POST /v1/proposals` — submit a proposal. The 202 response carries
  `accepted_chunk_ids` (one ID per operation the gateway accepted) and
  `rejection_reasons` (one entry per operation the gateway refused at
  submit-time). The two arrays together account for every operation you
  sent.
- `GET /v1/proposals/{chunk_id}` — immediate state of one proposal.
  Returns `status` (`pending` / `approved` / `rejected`),
  `rejection_reason` (the reviewer's free-form note, only set on reject),
  and `validation_result` (the gateway prover's verdict on this chunk;
  may be empty).
- `GET /v1/proposals/{chunk_id}/wait?timeout=<seconds>` — block on this
  proposal until the developer decides or the timeout expires. Default
  60s, clamped [1, 300]. On timeout you get `status: "pending"` plus
  `timed_out: true`. On approval the response also carries
  `policy_reloaded: true|false` indicating whether the local sandbox has
  already loaded a policy containing the approved rule. Use this endpoint
  instead of polling `/v1/proposals/{chunk_id}`.

The proposal body takes an `intent_summary` and one or more `addRule`
operations. Each `addRule` carries a complete narrow `NetworkPolicyRule`.

## Workflow

1. Read the denial response body. Use `layer`, `method`, `path`, `host`,
   `port`, `binary`, `rule_missing`, and `detail` as evidence.
2. Fetch the current policy from `/v1/policy/current`.
3. Fetch recent denials from `/v1/denials` if the response body is incomplete.
4. Prefer L7 REST rules for REST APIs. Use L4 only for non-REST protocols or
   when the client tunnels opaque traffic that OpenShell cannot inspect.
5. Draft the narrowest rule: exact host, exact port, exact binary when known,
   exact method, and the smallest safe path.
6. Submit the proposal, save `accepted_chunk_ids` from the response, and
   tell the developer what you proposed. If the response also carries
   `rejection_reasons`, the gateway refused those operations at
   submit-time before any human review; fix them and resubmit before
   waiting on the rest.
7. For each accepted chunk_id, call
   `GET /v1/proposals/{chunk_id}/wait?timeout=300` and act on the result:
   - `status: "approved"` with `policy_reloaded: true` — retry the
     original denied action. The merged policy is already loaded; the
     request should succeed. If it still fails with `policy_denied`,
     re-read the denial — your rule may not match. If it fails for any
     other reason, surface to the user.
   - `status: "approved"` with `policy_reloaded: false` — approval
     landed but the local sandbox hasn't observed the reload within the
     `/wait` window. Re-issue the same `/wait` call once with
     `timeout=30`. If the second response is still
     `policy_reloaded: false`, surface to the user rather than retrying
     blind; do not loop tightly.
   - `status: "rejected"` — read `rejection_reason` and
     `validation_result`. `rejection_reason` is what the reviewer typed;
     `validation_result` is the prover's verdict, which often explains
     a reject driven by automated checks. If either has content, address
     the specific feedback and submit a revised proposal. If both are
     empty, draft something materially different or ask the user.
   - `status: "pending"` with `timed_out: true` — call `/wait` again.
   - Any non-2xx response — surface to the user; do not retry the denied
     action without approval.

## Proposal shape

A complete narrow REST-inspected rule looks like this:

```json
{
  "intent_summary": "Allow gh to update repository contents in NVIDIA/OpenShell only.",
  "operations": [
    {
      "addRule": {
        "ruleName": "github_api_repo_contents_write",
        "rule": {
          "name": "github_api_repo_contents_write",
          "endpoints": [
            {
              "host": "api.github.com",
              "port": 443,
              "protocol": "rest",
              "enforcement": "enforce",
              "rules": [
                {
                  "allow": {
                    "method": "PUT",
                    "path": "/repos/NVIDIA/OpenShell/contents/**"
                  }
                }
              ]
            }
          ],
          "binaries": [
            {
              "path": "/usr/bin/gh"
            }
          ]
        }
      }
    }
  ]
}
```

## Norms

- Do not propose wildcard hosts such as `**` or `*.com`.
- Do not propose `access: full` to fix a single denied REST request.
- Do not include query strings, tokens, credentials, or secret values in
  paths.
- Explain uncertainty in `intent_summary` instead of widening the rule.
- If pushing with `git` fails, that is a separate L4 or protocol-specific
  path from GitHub REST API access. Propose it separately.

## Local logs (read-only)

Two local files complement the API and are useful when debugging policy
behavior:

- `/var/log/openshell.YYYY-MM-DD.log` — shorthand log of sandbox activity.
  This is what `/v1/denials` reads from.
- `/var/log/openshell-ocsf.YYYY-MM-DD.log` — full OCSF JSON events, only
  written when the `ocsf_json_enabled` setting is on. Not used by
  `/v1/denials`; useful for SIEM ingestion.
