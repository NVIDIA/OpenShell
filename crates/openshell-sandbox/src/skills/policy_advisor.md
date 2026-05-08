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
- `POST /v1/proposals` — submit a proposal for developer approval.

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
6. Submit the proposal, tell the developer what you proposed, and retry the
   denied action only after approval.

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
