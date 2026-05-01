# OpenShell Policy Advisor

Use this when OpenShell blocks a network request and the response or logs say
`policy_denied`.

## Goal

Draft the smallest policy proposal that allows the user's current task without
giving the sandbox broad new network access. The developer approves or rejects
the proposal; do not try to bypass policy.

## Local API

Use the sandbox-local policy API:

- `GET http://policy.local/v1/policy/current`
- `GET http://policy.local/v1/denials?last=10`
- `POST http://policy.local/v1/proposals`

The MVP proposal endpoint accepts a JSON object containing an `intent_summary`
and one or more `PolicyMergeOperation` objects. Start with a full `addRule`
operation because the existing developer inbox reviews complete draft rules.

You can also inspect your own logs:

- `/var/log/openshell.YYYY-MM-DD.log` is the default shorthand log.
- `/var/log/openshell-ocsf.YYYY-MM-DD.log` is present when OCSF JSONL logging is enabled.

## Workflow

1. Read the denial response body. Use `layer`, `method`, `path`, `host`,
   `port`, `binary`, `rule_missing`, and `detail` as evidence.
2. Fetch the current policy from `policy.local`.
3. Fetch recent denials if the response body is incomplete.
4. Prefer L7 REST rules for REST APIs. Use L4 only for non-REST protocols or
   when the client tunnels opaque traffic that OpenShell cannot inspect.
5. Draft the narrowest rule: exact host, exact port, exact binary when known,
   exact method, and the smallest safe path glob.
6. Submit the proposal, tell the developer what you proposed, and wait for
   approval before retrying the denied action.

## Proposal Shapes

Submit a complete narrow REST-inspected rule:

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

For GitHub repository creation, keep the path exact:

```json
{
  "intent_summary": "Allow gh to create a repository for the authenticated user.",
  "operations": [
    {
      "addRule": {
        "ruleName": "github_api_repo_create",
        "rule": {
          "name": "github_api_repo_create",
          "endpoints": [
            {
              "host": "api.github.com",
              "port": 443,
              "protocol": "rest",
              "enforcement": "enforce",
              "rules": [
                {
                  "allow": {
                    "method": "POST",
                    "path": "/user/repos"
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
- Do not include query strings, tokens, credentials, or secret values.
- Explain uncertainty in `intent_summary` instead of widening the rule.
- If pushing with `git` fails, that may be a separate L4 or protocol-specific
  path from GitHub REST API access; propose it separately.
