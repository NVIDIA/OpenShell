# OpenShell CLI Advanced Workflows

Use this reference with [SKILL.md](SKILL.md). Load only the workflow relevant to
the current task.

## Contents

- [BYOC](#byoc-bring-your-own-container)
- [Agent-assisted sandbox session](#agent-assisted-sandbox-session)
- [Gateway inference](#gateway-inference)
- [Gateway management](#gateway-management)
- [Settings management](#settings-management)
- [Service access](#service-access)

## BYOC (Bring Your Own Container)

Build a custom container image and run it as a sandbox.

### Create a sandbox from a Dockerfile

```bash
openshell sandbox create --from ./Dockerfile --name my-app
```

The `--from` flag accepts a Dockerfile path, a directory containing a Dockerfile,
a full image reference such as `myregistry.com/img:tag`, or a community sandbox
name such as `ollama`.

Local Dockerfile and directory builds require a local gateway because the CLI
builds through the local Docker daemon. Use a registry image reference for remote
gateways. Bare community names resolve under
`ghcr.io/nvidia/openshell-community/sandboxes` unless
`OPENSHELL_COMMUNITY_REGISTRY` overrides the prefix.

### Forward ports

```bash
# Foreground (blocks)
openshell forward start 8080 my-app

# Background (returns immediately)
openshell forward start 8080 my-app -d
```

The service is now reachable at `localhost:8080`.

Manage or iterate on the sandbox:

```bash
openshell forward list
openshell forward stop 8080 my-app
openshell sandbox delete my-app
openshell sandbox create --from ./Dockerfile --name my-app --forward 8080
```

Create and forward in one command:

```bash
openshell sandbox create --from ./Dockerfile --forward 8080 -- ./start-server.sh
```

The `--forward` flag starts a background port forward before the command runs.

## Agent-Assisted Sandbox Session

Support a human working in a sandbox while an agent monitors activity and refines
the policy in parallel.

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
openshell logs work-session --tail --source sandbox --level warn
```

When denied actions appear:

1. Prefer incremental updates for additive network changes:
   `openshell policy update work-session --add-endpoint api.github.com:443:read-only:rest:enforce --binary /usr/bin/gh --wait`
   `openshell policy update work-session --add-allow 'api.github.com:443:POST:/repos/*/issues' --wait`
2. Use full YAML replacement for broad changes or non-network fields:
   `openshell policy get work-session --full > policy.yaml`
   Modify the policy with the `generate-sandbox-policy` skill.
   `openshell policy set work-session --policy policy.yaml --wait`
3. Verify with `openshell policy list work-session`.

The user does not need to disconnect. Policy updates are hot-reloaded; `--wait`
blocks until the sandbox confirms the revision or the timeout expires. Delete the
sandbox when the session ends:

```bash
openshell sandbox delete work-session
```

## Gateway Inference

Configure the gateway's user-facing `inference.local` route or the system
inference route used by platform functions.

Ensure the provider exists, then set the route:

```bash
openshell provider list
openshell inference set \
  --provider nvidia \
  --model nvidia/nemotron-3-nano-30b-a3b
```

This updates the gateway-managed `inference.local` route. Endpoint verification
runs before the route is saved. Use `--no-verify` only when verification is
intentionally impossible, and use `--timeout SECONDS` to configure the request
timeout. Add `--system` to `set` or `update` for the platform-only system route.

Inspect both configurations:

```bash
openshell inference get
openshell inference get --system
```

Agents send HTTPS requests to `inference.local`; the sandbox intercepts them and
routes them through the gateway inference config. Sandbox policy remains separate
from gateway inference configuration.

## Gateway Management

List, switch, and verify gateways:

```bash
openshell gateway select
openshell gateway list --output json
openshell gateway select production
openshell gateway info --name production
openshell status
```

Register or remove gateways:

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local
openshell gateway add https://gateway.example.com --name production
openshell gateway remove local
```

`https://` registrations default to edge authentication. Use `gateway login` and
`gateway logout` to refresh or clear stored authentication. For an OIDC gateway,
supply `--oidc-issuer` and, when needed, `--oidc-client-id`, `--oidc-audience`, and
`--oidc-scopes`. For remote mTLS gateways, use `--remote USER@HOST` or an `ssh://`
endpoint.

For one-off automation, `--gateway-endpoint URL` connects directly without stored
metadata. Limit `--gateway-insecure` to explicitly trusted development endpoints.

Inspect a Kubernetes deployment:

```bash
helm -n openshell status openshell
kubectl -n openshell get deployment,statefulset,pods,svc
kubectl -n openshell logs deployment/openshell -c openshell-gateway --tail=100
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=100
```

For Docker, Podman, and VM-backed gateways, inspect the gateway process or
container logs and the selected runtime directly.

## Settings Management

Manage sandbox-scoped or gateway-global settings:

```bash
openshell settings get work-session
openshell settings set work-session --key ocsf_json_enabled --value true
openshell settings delete work-session --key ocsf_json_enabled

openshell settings get --global --json
openshell settings set --global --key providers_v2_enabled --value true
```

Global mutations prompt for confirmation. Use `--yes` only in reviewed automation.

## Service Access

Use `forward` for local access and `service` for a gateway-managed HTTP endpoint:

```bash
# SSH-based same-port forwarding; optional bind address is accepted.
openshell forward start 127.0.0.1:8080 my-app -d

# gRPC relay to a loopback TCP service, with an optional dynamic local port.
openshell forward service my-app --target-port 8000 --local 127.0.0.1:0

# Expose and manage an HTTP service through the gateway.
openshell service expose my-app 8080 web
openshell service list my-app
openshell service get my-app web
openshell service delete my-app web
```

Prefer loopback binds unless the user explicitly needs LAN-visible local access.
