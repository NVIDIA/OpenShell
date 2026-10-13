# Providers and profiles

Providers supply credentials and provider-specific configuration to sandboxes. `openshell agent context` lists the exact flags.

Providers supply credentials and provider-specific configuration to sandboxes. Provider profiles are import-only: a gateway serves exactly what an operator imported, and a new gateway serves an empty catalog. Never rely on a hard-coded type list or on a legacy alias such as `gh` or `claude` — `--type` matches a profile ID exactly. Discover the profiles available on the selected gateway:

```shell
openshell profile list
openshell profile list --type provider --output json
```

## Create a provider from local credentials

```bash
openshell provider create --name my-github --type github --from-existing
```

The `--from-existing` flag discovers credentials from local state (e.g., `gh auth` tokens, Claude config files).

## Create a provider with explicit credentials

```bash
openshell provider create --name my-openai --type openai \
  --credential OPENAI_API_KEY
```

Bare `KEY` reads the value from the environment variable of that name and avoids placing the secret in shell history. Use `KEY=VALUE` only when the user explicitly accepts that exposure.

Other credential sources are `--from-gcloud-adc` for compatible profiles and `--runtime-credentials` when the gateway or sandbox resolves the required credentials at runtime.

Static provider credentials resolve only for hosts, ports, and paths declared by
the provider profile. Use `profile export` to inspect that boundary
when a placeholder is present but requests receive
`credential_endpoint_mismatch`. A profileless static provider fails closed
because the gateway cannot construct a binding.

When an inspected request receives `request_authority_mismatch`, compare its
HTTP authority with the CONNECT tunnel endpoint. The host and effective port
must match. For a tunnel to `api.example.com:8443`, send
`Host: api.example.com:8443`; `Host: api.example.com` omits the non-default
port and is rejected. An absolute-form request target must use the same
authority.

Profile-backed providers always contribute policy unless a gateway-global
policy is active. Static credential endpoint binding remains independently
enforced.

## Label and select providers

Attach labels during provider creation with repeatable `--label KEY=VALUE`
flags. Labels work with each credential source. List selectors require every
comma-separated key-value pair to match and apply before pagination.

```shell
openshell provider create --name public-pypi --type pypi --label env=dev --label team=ml
openshell provider list --label-selector env=dev,team=ml
openshell provider list --all-workspaces --label-selector team=ml --output json
openshell provider get public-pypi
```

Use an imported profile, such as `pypi` in this example. `get` displays labels;
structured list output includes them. `--all-workspaces` requires Platform
Admin access. Preserve the selector and workspace scope when passing the next
`--page-token`. Labels cannot be changed or removed after provider creation.

## Inspect and manage provider profiles

```shell
openshell profile describe github
openshell profile export github --output yaml
openshell profile lint --file ./my-profile.yaml
openshell profile import --file ./my-profile.yaml
openshell profile lint --url https://example.com/profiles/my-profile.yaml
openshell profile import --url https://example.com/profiles/my-profile.yaml
```

`--url` accepts one HTTP or HTTPS YAML or JSON profile. Review its endpoint and
binary grants before importing it. The URL path must end in `.yaml`, `.yml`, or
`.json`; downloads are limited to 1 MiB and 15 seconds.

Use `profile describe` to inspect a definition's credential metadata, endpoints, TLS handling, MCP access settings, rule counts, binaries, source, and scope before creating a provider. Check for `tls: skip` and the uninspected-credential opt-in before relying on displayed L7 rules. List and describe accept table, JSON, and YAML output; use structured output for complete rule definitions, `--workspace` for a workspace catalog, or `--global` for platform scope. Use `profile export` when preparing an editable definition, `profile update <id> --file <file>` to replace an existing custom profile with its current resource version, and `profile delete <id>...` to remove custom profiles. Provider instances remain under `provider`.

Existing scripts can continue using `provider list-profiles` and `provider profile export/import/update/lint/delete`. These commands share the top-level handlers and preserve their arguments, output options, and workspace/global flags. Prefer `profile` when writing new commands.

## List, inspect, update, delete

Use `openshell sandbox provider status --help` and the attach, detach, and update help to find the installed version's wait options. Add `--wait` when the next step depends on a provider change taking effect. Without it, a successful command only confirms that the gateway saved the change. Save the returned `receipt_id` to check that same change later, and inspect the result for every selected sandbox. Credential refresh status confirms that OpenShell obtained credentials; provider status confirms that the sandbox applied them, activated the policy, and updated the environment for new processes. If the status is `superseded`, explain that a later change replaced the request and inspect that change separately.

If attach, detach, or update reports `CONFIG_OPERATION_STORAGE_UNCERTAIN`, explain that the change may already be saved and its readiness receipt may be unavailable. Do not blindly retry the mutation. Inspect the provider and sandbox state and reconcile the saved change before deciding on another mutation; the error proves neither rollback nor readiness.

```bash
openshell provider list
openshell provider list --output json
openshell provider get my-github
openshell provider update my-github --from-existing
openshell provider delete my-github
```

`provider update` does not take `--type`. It updates credentials, config, or credential expiry on the existing provider.

For an external updater whose workload must retain its original environment reference, use a credential profile with `stable_placeholder: true` and a gateway and supervisor that support that mode. The CLI checks gateway support before importing or updating the opt-in. The default remains `false`, preserving existing revision-scoped behavior and ordinary legacy gateway operation. Preserve the supervisor-issued value; never manufacture a placeholder. After the supervisor installs a value-only update, the retained reference resolves the current credential only at its effective host, port, and path binding. Replacement, expiry, changed binding, or an activated detach prevents old authority from resolving. Remove the opt-in and activate that change before downgrading the gateway. See the provider profiles documentation for the lifecycle contract and its separation from gateway-managed refresh and `token_grant`.

## Configure credential refresh

Use refresh commands only when the provider profile and gateway support refreshable credentials:

```bash
openshell provider refresh status my-provider
openshell provider refresh configure my-provider \
  --credential-key MS_GRAPH_ACCESS_TOKEN \
  --strategy oauth2-refresh-token \
  --secret-material-env REFRESH_TOKEN=MS_GRAPH_REFRESH_TOKEN \
  --credential-expires-at 2026-07-16T00:00:00Z
openshell provider refresh rotate my-provider --credential-key ACCESS_TOKEN
```

Prefer `--secret-material-env KEY[=ENVVAR]` for secret refresh material. `--material KEY=VALUE` is for non-secret material; `--secret-material-key` marks supplied material keys as secret.

The gateway stores secret refresh material through its active credential driver.
With Vault selected, refresh tokens, client secrets, and private keys live in
Vault alongside injectable provider credentials; refresh state contains only
opaque handles. A credential-backend read or write failure makes refresh fail
closed rather than falling back to inline storage. Before OpenShell 0.1.0, the
gateway does not migrate legacy inline refresh material or move secrets between
credential backends. Reconfigure affected grants after upgrading, and remove or
reconfigure credentials while the original backend remains available before
changing backends. Do not run mixed gateway versions against the same refresh
records.

Gateway-managed refresh credentials use an identity-stable workload handle.
Routine automatic refresh and `provider refresh rotate` update the access token
behind that handle, so long-running processes do not need to restart. Running
processes must be restarted once when upgrading from revision-scoped
placeholders. A later `provider refresh configure` call is an explicit
reauthorization boundary: it revokes the previous handle, and processes holding
that handle fail closed until restarted.

While gateway-managed refresh is configured, `provider update --credential`
cannot replace or delete the refresh-owned primary credential or any co-minted
output. Use `provider refresh rotate`, reconfigure refresh, or delete refresh
before returning those keys to manual management. Unrelated provider fields
remain updateable.

When OAuth refresh fails, inspect the `RECOVERY` and `FAILURE_CODE` columns from
`provider refresh status`; do not infer the remedy from HTTP status or parse
`LAST_ERROR`. `retry` means the worker will try again, `reauthorize` means the
user must obtain a new OAuth grant and run `provider refresh configure`,
`fix_configuration` means an operator must repair the OAuth client, scopes, or
administrator policy, and `investigate` can mean an unrecognized issuer
response or an interrupted mint with an uncertain outcome. The gateway parks
`reauthorize` records until a manual rotate or reconfiguration. It retries
`fix_configuration` records hourly so externally repaired configuration can
recover without rapid token-endpoint traffic. The existing access credential
remains usable only until its recorded expiry.

`refresh_in_progress` and `refresh_committing` can indicate active work. Check
gateway health and refresh status again before treating them as failures;
concurrent refresh requests wait for the active mint. If a gateway interruption
leaves either marker behind and rotation reports an uncertain previous mint,
the gateway will not reuse the grant automatically. Investigate the issuer state,
then run `provider refresh configure` with a valid grant. Obtain a new OAuth
grant first if the previous refresh token may have been consumed. Do not clear
the marker directly or repeatedly rotate it; reconfiguration revokes old
workload handles, so restart processes holding them.
