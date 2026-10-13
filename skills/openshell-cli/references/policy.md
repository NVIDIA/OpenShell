# Policy iteration

Refine a sandbox's network policy from observed activity, review agent-authored rule proposals, and manage gateway-global policy. For policy YAML content, use the `generate-sandbox-policy` skill.

## Iteration loop

This is the most important multi-step workflow. It enables a tight feedback cycle where sandbox policy is refined based on observed activity.

**Key concept**: Policies have static fields (immutable after activation: `filesystem_policy`, `landlock`, `process`) and two dynamic fields: `network_policies` and `network_middlewares`. Both dynamic fields can be updated without recreating the sandbox when the selected compute driver supports live policy updates. Drivers without the standard supervisor fetch revisions through the sandbox configuration API and report whether they loaded them.

If startup reports `ConfigurationInvalid`, inspect `openshell sandbox get` and
repair the complete policy or provider set through the gateway. The workload
has not started on its first activation, so static fields can also be replaced
during this initial repair. A previously activated sandbox retains static-field
restrictions while restart admission is pending or rejected.
Before the gateway's 300-second repair window expires, successful validation
completes startup in place. Effective stored configuration changes and their
first failed load reset that window; repeated failures do not. After
`ProvisioningTimedOut`, inspect the retained record and cleanup status, repair
configuration, and explicitly run `sandbox start` once cleanup completes. A CLI
wait timeout is separate from this gateway deadline. Follow the
published [policy repair guidance](https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview)
and confirm current replacement/detach syntax with installed CLI help.

An endpoint with omitted `protocol` retains explicit-proxy behavior. Explicit
`protocol: tcp` requests policy DNS and transparent TCP and currently requires
the Docker or Podman runtime; unsupported runtimes reject the policy before starting the
workload rather than activating only part of the network contract.

```
Create sandbox with initial policy
        │
        ▼
   Monitor logs ◄──────────────────┐
        │                          │
        ▼                          │
  Observe denied actions           │
        │                          │
        ▼                          │
  Pull current policy              │
        │                          │
        ▼                          │
  Modify policy YAML               │
  (use generate-sandbox-policy)    │
        │                          │
        ▼                          │
  Push updated policy              │
        │                          │
        ▼                          │
  Verify reload succeeded ─────────┘
```

### Step 1: Create sandbox with initial policy

```bash
openshell sandbox create --name dev --from registry.example.com/your-org/claude-agent:latest --policy ./initial-policy.yaml -- claude
```

Sandboxes stay alive by default for iteration. Add `--no-keep` only when the sandbox should be deleted automatically after the initial session.

### Step 2: Monitor logs for denied actions

In a separate terminal or as the agent:

```bash
openshell logs dev --tail --source sandbox
```

Look for `DENIED` log lines. `NET:OPEN [MED] DENIED` marks a blocked connection, and `HTTP:<METHOD> [MED] DENIED` marks a blocked request. Policy events are INFO-level log records, so do not add `--level warn`. The logs include:

- **Destination host and port** (what was blocked)
- **Binary path** (which process attempted the connection)
- **Deny reason** (why it was blocked)

### Step 3: Pull the current policy

```bash
set -o pipefail
openshell policy get dev --base | sed '1,/^---$/d' > current-policy.yaml
```

`--base` returns the editable policy without provider-composed entries; OpenShell composes attached provider rules separately. The command prints revision details, a `---` line, and then the policy YAML. The `sed` expression keeps only the YAML, because `policy set` cannot parse the revision details. Use `--full` only to inspect the effective policy, not as input to `policy set`.

To view the active policy without editing it, run `openshell sandbox get dev --policy-only`. It prints only the effective policy YAML, so like `--full` it is not input for `policy set`.

### Step 4: Modify the policy

Edit `current-policy.yaml` to allow the blocked actions. **For policy content authoring, delegate to the `generate-sandbox-policy` skill.** That skill handles:

- Network endpoint rule structure
- L4 vs REST, WebSocket, JSON-RPC, and MCP L7 policy decisions
- Access presets (`read-only`, `read-write`, `full`)
- TLS termination configuration
- Enforcement modes (`audit` vs `enforce`)
- Binary matching patterns
- Ordered `network_middlewares`, host selection, HTTP request/response and WebSocket bindings, and `fail_open` or `fail_closed` behavior

`network_policies` and `network_middlewares` can be modified at runtime when the selected compute driver supports live policy updates. Use `--wait` to verify that the active runtime loaded the revision; do not infer enforcement from the gateway accepting the update. If `filesystem_policy`, `landlock`, or `process` need changes, the sandbox must be recreated. Built-in middleware such as `openshell/regex` needs no gateway registration. An operator-run middleware must already be registered under `[[openshell.supervisor.middleware]]`; changing that static registration requires a gateway restart.

Middleware can inspect HTTP requests, HTTP responses, or client WebSocket text
messages when the implementation advertises the matching binding. The built-in
`openshell/regex` supports request bodies and client WebSocket text messages.
Use the `generate-sandbox-policy` skill to choose attachments and failure policy,
and `debug-openshell-cluster` to investigate middleware failures.

### Step 5: Push the updated policy

Check the file locally, then push it:

```bash
openshell policy validate --policy current-policy.yaml
openshell policy set dev --policy current-policy.yaml --wait
```

`policy validate` runs the gateway's schema and safety checks without contacting it and prints every violation.

The gateway validates the complete effective candidate—including attached
provider-profile policy—before it stores a direct update, incremental merge,
approved proposal, provider attachment, or profile update that affects attached
sandboxes. An ambiguity failure returns `FAILED_PRECONDITION`; the rejected
candidate does not create a policy revision or partially update affected
sandboxes. The same fail-closed response applies when `credential_signing`
does not have an attached AWS profile whose credential boundary covers the
endpoint, or an explicit binding to an endpointless AWS profile. Fix the
conflicting endpoint selectors or credential source and submit again.

The `--wait` flag blocks until the sandbox confirms the policy is loaded (polls every second). Exit codes:

- **0**: Policy loaded successfully
- **1**: Policy load failed
- **124**: Timeout (default 60 seconds)

### Step 6: Verify the update

```bash
openshell policy list dev
```

Check that the latest revision shows status `loaded`. If `failed`, check the error column for details.

### Step 7: Repeat

Return to Step 2. Continue monitoring logs and refining the policy until all required actions are allowed and no unnecessary permissions exist.

## Policy revision history

View all revisions to understand how the policy evolved:

```bash
openshell policy list dev --page-size 50
openshell policy list dev --output json
```

Fetch a specific historical revision:

```bash
openshell policy get dev --rev 3 --full
```

Gateway-global policy commands use `--global` and require confirmation unless `--yes` is supplied:

```bash
openshell policy get --global --full
openshell policy set --global --policy ./global-policy.yaml
openshell policy list --global
openshell policy delete --global
```

Avoid `--yes` during interactive work. A global policy locks policy control for all sandboxes on the gateway.

## Review agent-authored rule proposals

Sandboxes created with `--approval-mode manual` place every proposal in the review inbox. `auto` approves only valid effective-policy candidates with an empty prover delta; findings still require review. The CLI binds approval to the candidate's current review token. If live policy, provider, or credential inputs change, approval leaves the chunk pending with a refreshed candidate and requires a fresh review.

```bash
openshell rule get dev --status pending
openshell rule approve dev --chunk-id <chunk-id>
openshell rule reject dev --chunk-id <chunk-id> --reason "too broad"
openshell rule history dev
```

Review the proposed scope, candidate hash, prover findings, and application errors before approval. Treat `rule approve-all --include-security-flagged` as a high-risk bulk action.

`validation unavailable` blocks approval until the gateway can analyze both the current and proposed policies. It is not an accepted-risk finding.

## Agent-assisted session

Support a human working in a sandbox while an agent monitors activity and refines the policy in parallel.

Create the sandbox and keep it alive:

```bash
openshell sandbox create \
  --name work-session \
  --provider github \
  --provider claude \
  --policy ./dev-policy.yaml
```

Tell the user to connect in another shell:

```bash
openshell sandbox connect work-session
openshell sandbox connect work-session --editor vscode
```

Monitor denied activity:

```bash
openshell logs work-session --tail --source sandbox
```

When denied actions appear:

1. Prefer incremental updates for additive network changes:
   `openshell policy update work-session --add-endpoint api.github.com:443:read-only:rest:enforce --binary /usr/bin/gh --wait`
   `openshell policy update work-session --rule-name allow_api_github_com_443 --binary /usr/bin/gh --add-allow 'api.github.com:443:POST:/repos/*/issues' --wait`

   A rule authorizes every binary it lists to reach every endpoint it lists, so
   an update that adds a binary or an endpoint to an existing rule must declare
   that rule's whole binary and endpoint scope. The gateway rejects an update
   that would grant a binary-to-endpoint pair the update never asked for, and
   the error names the binaries still missing. To grant one binary access to
   only part of a rule's endpoints, send the narrow authorization under its own
   `--rule-name`; it stays on its own rule instead of folding into the broader
   one.

   `--add-allow` and `--add-deny` require `--rule-name` and the complete binary scope through repeated `--binary` or explicit `--any-binary`. Declare every port on the endpoint in the operation, for example `api.example.com:443,8443:POST:/admin`. Use `--endpoint-path` to disambiguate endpoints within the selected rule; an explicitly empty path selects an endpoint without a path selector. The gateway rejects missing or mismatched scope before persistence. Inspect the current policy and confirm the intended affected scope; do not automatically fill declarations from current policy just to make a rejection pass.
2. Use full YAML replacement for broad network changes or settings that
   `policy update` cannot express, including any change that would otherwise
   require restating a large existing scope. Filesystem, Landlock, and process
   changes still require recreating the sandbox:
   `openshell policy get work-session --base | sed '1,/^---$/d' > policy.yaml`
   Modify the policy with the `generate-sandbox-policy` skill.
   `openshell policy set work-session --policy policy.yaml --wait`
3. Verify with `openshell policy list work-session`.

The user does not need to disconnect. Policy updates are hot-reloaded; `--wait` blocks until the sandbox confirms the revision or the timeout expires. Delete the sandbox when the session ends:

```bash
openshell sandbox delete work-session
```
