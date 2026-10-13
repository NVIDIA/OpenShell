# Gateways and settings

Register, authenticate, select, and inspect gateways, and manage sandbox and gateway-global settings.

## Register and verify a gateway

### Register a gateway

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local
```

Use an `http://` endpoint only for trusted local port-forwarding or a protected private path. For a gateway behind an authenticated reverse proxy, register its HTTPS endpoint with `openshell gateway add https://gateway.example.com`.

### Verify the gateway

```bash
openshell status
openshell whoami
```

Confirm the gateway is reachable, authentication is valid or not required, and
the output shows a version. `Status: Connected` only proves the public health
endpoint is reachable; inspect the separate `Authentication` line before
running protected commands. `openshell whoami` reports the identity validated
by the gateway, including the subject an administrator uses for workspace
membership. Add `--output json` for automation.

## Manage gateways

List, switch, and verify gateways:

```bash
openshell gateway select
openshell gateway list --output json
openshell gateway select production
openshell --gateway production gateway info
openshell status
```

`openshell gateway info` reports the immutable startup snapshot for compute drivers, credential drivers, gateway interceptors, and supervisor middleware. Use each entry's protocol version, implementation version, supported capabilities, and gateway requirements when diagnosing extension skew; implementation versions do not identify underlying Docker, Kubernetes, or credential backends.

Register or remove gateways:

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local
openshell gateway add https://gateway.example.com --name production
openshell gateway remove local
```

`https://` registrations default to edge authentication. Use `gateway login` and `gateway logout` to refresh or clear stored authentication. For an OIDC gateway, supply `--oidc-issuer` and, when needed, `--oidc-client-id`, `--oidc-audience`, and `--oidc-scopes`. If automatic OIDC refresh fails, protected commands stop before sending an RPC and direct the user to run `openshell gateway login <name>`; `openshell status` still reports gateway reachability and authentication separately. For remote mTLS gateways, use `--remote USER@HOST` or an `ssh://` endpoint.

For one-off automation, `--gateway-endpoint URL` connects directly without stored metadata. Limit `--gateway-insecure` to explicitly trusted development endpoints.

Inspect a Kubernetes deployment:

```bash
helm -n openshell status openshell
kubectl -n openshell get deployment,statefulset,pods,svc
kubectl -n openshell logs deployment/openshell -c openshell-gateway --tail=100
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=100
```

For Docker, Podman, and VM-backed gateways, inspect the gateway process or container logs and the selected runtime directly.

## Settings

Manage sandbox-scoped or gateway-global settings:

```bash
openshell settings get work-session
openshell settings set work-session --key ocsf_json_enabled --value true
openshell settings delete work-session --key ocsf_json_enabled

openshell settings get --global --json
openshell settings set --global --key ocsf_json_enabled --value true

# OCSF schema version downgrade for SIEM compatibility (allowed: "1.1", "1.3")
openshell settings set --global --key ocsf_schema_version --value "1.1"
```

Enabling `ocsf_json_enabled` adds compact `OCSF-JSON` records to the supervisor's stderr, alongside shorthand, and to its JSONL file when file storage is available. Collect these records through the supervisor's platform logs (`docker logs`, `podman logs`, or `kubectl logs`); `openshell logs` still serves shorthand. Match the `OCSF-JSON` marker after the timestamp and parse the remainder as JSON. See the published [OCSF JSON export guide](https://docs.nvidia.com/openshell/latest/observability/ocsf-json-export) for delivery and retention limits.

Global mutations prompt for confirmation. Use `--yes` only in reviewed automation.

`policy_validation_failure_mode` is gateway startup configuration, not a
mutable `openshell settings` key. Set it under `[openshell.gateway]` in
`gateway.toml` and restart the gateway. The security-first default is
`fail_closed`; `retain_last_valid` is an explicit availability tradeoff. OCSF
configuration events state whether the previous generation is active after a
runtime validation failure.
