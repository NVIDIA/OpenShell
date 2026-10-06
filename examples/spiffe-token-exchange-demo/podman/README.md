# Podman SPIFFE Token Exchange Demo

This variant runs the SPIFFE token exchange demo with local Podman containers
instead of Kubernetes workloads.

The first version is intentionally single-sandbox. The script creates one
concrete SPIRE registration entry for the sandbox after Ryno creates it.
It does not rely on SPIRE templating one entry into many per-sandbox SPIFFE IDs.

## What Runs

`demo.sh` starts these local Podman containers on the `ryno` network by
default:

| Container | Purpose |
|---|---|
| `ryno-spiffe-demo-spire-server` | Local SPIRE server |
| `ryno-spiffe-demo-spire-agent` | Local SPIRE agent with a Workload API socket |
| `ryno-spiffe-demo-spire-oidc` | SPIRE OIDC discovery provider for JWKS |
| `ryno-spiffe-demo-token-issuer` | Dummy IdP/token exchange endpoint |
| `ryno-spiffe-demo-alpha` | Protected alpha service |
| `ryno-spiffe-demo-beta` | Protected beta service |

The Ryno gateway is not started by this script. Start it separately with
the Podman driver and SPIFFE provider token grant settings.

For the most self-contained path, set `START_GATEWAY=1`. The script starts a
gateway container on the same Podman network as the token issuer and protected
services. That makes Podman's DNS alias
`token-exchange-issuer.default.svc.cluster.local` resolve inside the gateway
without host DNS changes.

## Gateway Requirements

Start the gateway with:

```shell
export RYNO_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=/path/to/demo/spire-agent.sock
```

Configure the Podman driver with the same socket path:

```toml
[ryno.drivers.podman]
network_name = "ryno"
provider_spiffe_workload_api_socket = "/path/to/demo/spire-agent.sock"
```

When `demo.sh` starts SPIRE itself, it prints the exact socket path to use.
Restart the gateway with that path before the final alpha/beta calls if the
gateway was not already configured.

The provider profile uses
`http://token-exchange-issuer.default.svc.cluster.local:8080/token` by default.
The token issuer container has that Podman network alias, so sandboxes on the
same Podman network can resolve it. The gateway also performs the intermediate
token exchange, so a host-running gateway must be able to resolve and reach the
same name. For local testing, add a hosts/DNS entry that maps
`token-exchange-issuer.default.svc.cluster.local` to the host address serving
the published `TOKEN_ISSUER_PORT`, or run the gateway in an environment attached
to the same Podman network.

`START_GATEWAY=1` automates that same-network gateway setup. It mounts the host
Podman socket into the gateway container, writes a temporary gateway config with
`compute_driver = "podman"`, and mounts the SPIRE Workload API socket at the
same absolute host path so the gateway can pass that path to sibling sandbox
containers.

The script looks for a Podman API socket in the usual rootless and rootful
locations, plus `podman system connection list`. If none exists, it starts a
temporary rootless API service under the script's temporary directory and stops
it during cleanup. The self-started socket is mounted into demo containers with
Podman relabeling. Set `PODMAN_SOCKET=/path/to/podman.sock` or
`PODMAN_SOCKET=unix:///path/to/podman.sock` to use a specific existing socket.
The SPIRE agent and managed gateway containers run with
`--security-opt label=disable` because both must connect to the rootless Podman
API Unix socket.

SPIRE runs as a non-root user in its upstream images. The script creates
throwaway state and socket directories under its temporary directory with broad
write permissions so rootless Podman UID mappings can create the SQLite
datastore and Workload API sockets.

## Run

From anywhere:

```shell
export RYNO_REPO=/path/to/Ryno
export GATEWAY_NAME=local
export GATEWAY_ENDPOINT=http://127.0.0.1:8080

bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/demo.sh"
```

Self-contained local path:

```shell
START_GATEWAY=1 \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/demo.sh"
```

Common overrides:

```shell
SANDBOX_NAME=spiffe-podman-demo
PODMAN_NETWORK=ryno
TOKEN_ISSUER_PORT=18080
MANAGED_GATEWAY_PORT=18082
MANAGED_GATEWAY_HEALTH_PORT=18083
GATEWAY_IMAGE=ghcr.io/nvidia/ryno/gateway:latest
SANDBOX_IMAGE=nvcr.io/nvidia/base/ubuntu:24.04
SUPERVISOR_IMAGE=ghcr.io/nvidia/ryno/supervisor:latest
SANDBOX_IMAGE_PULL_POLICY=if_not_present
PODMAN_STOP_TIMEOUT_SECS=3
KEEP_DEMO=1
KEEP_SANDBOX=1
```

Keep `SANDBOX_NAME` at 19 characters or fewer for the Podman driver. The
default `spiffe-podman-demo` is 18 characters.

`PODMAN_STOP_TIMEOUT_SECS` controls how long the managed gateway asks Podman to
wait for sandbox containers to stop before Podman force-kills them during
cleanup. The short demo default avoids waiting on long SIGTERM grace periods.

When testing branch-local images with `START_GATEWAY=1`, override all three
Ryno runtime images:

```shell
START_GATEWAY=1 \
GATEWAY_IMAGE=localhost/ryno/gateway:branch \
SANDBOX_IMAGE=localhost/ryno/sandbox:branch \
SUPERVISOR_IMAGE=localhost/ryno/supervisor:branch \
SANDBOX_IMAGE_PULL_POLICY=never \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/demo.sh"
```

`SANDBOX_IMAGE` renders to `[ryno.drivers.podman].default_image`.
`SUPERVISOR_IMAGE` renders to `[ryno.drivers.podman].supervisor_image`.

Use `START_SPIRE=0` only when you already have SPIRE running and can provide a
host path to a Workload API socket:

```shell
START_SPIRE=0 \
SPIRE_AGENT_SOCKET_HOST_PATH=/run/spire/agent.sock \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/demo.sh"
```

## SPIRE Startup Scripts

The full demo uses these scripts internally, and you can also run them directly
when you want to manage SPIRE separately from the token exchange flow:

```shell
SPIRE_STATE_DIR="$(mktemp -d)" \
SPIRE_ENV_FILE=/tmp/ryno-spire-server.env \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/spire/start-server-oidc.sh"

source /tmp/ryno-spire-server.env

SPIRE_STATE_DIR="$(mktemp -d)" \
SPIRE_ENV_FILE=/tmp/ryno-spire-agent.env \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/spire/start-agent.sh"

source /tmp/ryno-spire-agent.env
printf "Workload API socket: %s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
```

`start-server-oidc.sh` starts the SPIRE server and OIDC discovery provider.
`start-agent.sh` generates a join token from the server container and starts a
SPIRE agent with the Docker-compatible Podman workload attestor. Both scripts
honor the same image, container, network, trust-domain, and SPIRE parent ID
environment variables as `demo.sh`.

## Gateway Startup Script

After starting the SPIRE agent, start a Podman-backed Ryno gateway with:

```shell
SPIRE_AGENT_ENV_FILE=/tmp/ryno-spire-agent.env \
GATEWAY_ENV_FILE=/tmp/ryno-spiffe-gateway.env \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/start-gateway.sh"
```

The gateway listens on `http://127.0.0.1:8888` by default, with health checks on
`http://127.0.0.1:8889`. Override those ports with `GATEWAY_PORT` and
`GATEWAY_HEALTH_PORT`.

`start-gateway.sh` mounts the SPIRE agent Workload API socket into the gateway
container and writes a temporary gateway config with the Podman driver enabled.
Register the gateway SPIFFE entry as a separate step:

```shell
GATEWAY_SELECTORS="docker:label:ryno.spiffe-demo:gateway" \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/spire/register-gateway.sh"
```

The script also honors `GATEWAY_IMAGE`, `SANDBOX_IMAGE`, `SUPERVISOR_IMAGE`,
`SANDBOX_IMAGE_PULL_POLICY`, `PODMAN_NETWORK`, `PODMAN_SOCKET`, and
`PODMAN_STOP_TIMEOUT_SECS`.

To require OIDC login for user-facing gateway calls, set `GATEWAY_OIDC_ISSUER`.
The script then renders `[ryno.gateway.oidc]` and defaults
`allow_unauthenticated_users` to `false`:

```shell
SPIRE_AGENT_ENV_FILE=/tmp/ryno-spire-agent.env \
GATEWAY_OIDC_ISSUER=https://idp.example.com/realms/ryno \
GATEWAY_OIDC_AUDIENCE=ryno-cli \
GATEWAY_OIDC_CLIENT_ID=ryno-cli \
GATEWAY_OIDC_LOGIN_SCOPES="openid profile email" \
bash "$RYNO_REPO/examples/spiffe-token-exchange-demo/podman/start-gateway.sh"
```

The script prints the matching `ryno gateway add ... --oidc-issuer ...`
command after the gateway is ready. You can also run it directly:

```shell
ryno gateway add http://127.0.0.1:8888 \
  --name podman-spiffe-demo \
  --oidc-issuer https://idp.example.com/realms/ryno \
  --oidc-client-id ryno-cli \
  --oidc-audience ryno-cli \
  --oidc-scopes "openid profile email"
```

OIDC-related overrides:

- `GATEWAY_OIDC_ISSUER`
- `GATEWAY_OIDC_AUDIENCE`, default `ryno-cli`
- `GATEWAY_OIDC_JWKS_TTL_SECS`, default `3600`
- `GATEWAY_OIDC_ROLES_CLAIM`, default `realm_access.roles`
- `GATEWAY_OIDC_ADMIN_ROLE`, default `ryno-admin`
- `GATEWAY_OIDC_USER_ROLE`, default `ryno-user`
- `GATEWAY_OIDC_SCOPES_CLAIM`, default empty
- `GATEWAY_OIDC_CLIENT_ID`, default `ryno-cli`
- `GATEWAY_OIDC_LOGIN_SCOPES`, default empty
- `GATEWAY_ALLOW_UNAUTHENTICATED_USERS`, default `false` when OIDC is enabled
  and `true` otherwise

## SPIRE Registration

The helpers are:

```shell
examples/spiffe-token-exchange-demo/podman/spire/register-gateway.sh
examples/spiffe-token-exchange-demo/podman/spire/register-sandbox.sh <sandbox-id>
```

Defaults:

- SPIRE agent parent ID:
  `spiffe://ryno.local/ryno/spire-agent/demo`
- Gateway SPIFFE ID:
  `spiffe://ryno.local/ryno/gateway/demo`
- Gateway selectors:
  `unix:uid:<current-uid>` plus `unix:path:<ryno-server-path>` when
  `ryno-server` is on `PATH`
- Managed gateway selectors:
  `docker:label:ryno.spiffe-demo:gateway`
- Sandbox SPIFFE ID:
  `spiffe://ryno.local/ryno/sandbox/<sandbox-id>`
- Sandbox selectors:
  `docker:label:ryno.managed:true` and
  `docker:label:ryno.ai/sandbox-id:<sandbox-id>`

If your gateway binary is not named `ryno-server` or is not on `PATH`, set
`GATEWAY_WORKLOAD_PATH` or provide `GATEWAY_SELECTORS`:

```shell
GATEWAY_WORKLOAD_PATH=/path/to/ryno-server \
  examples/spiffe-token-exchange-demo/podman/spire/register-gateway.sh
```

If your SPIRE setup cannot use Docker-style selectors against Podman, provide
explicit selectors:

```shell
SANDBOX_SELECTORS="selector:a selector:b" \
  examples/spiffe-token-exchange-demo/podman/spire/register-sandbox.sh "$SANDBOX_ID"
```

## Expected Output

The alpha and beta calls should include the demo user and the sandbox SPIFFE ID:

```text
alpha called with path /:
  sub: demo-user
  aud: alpha, account
  scope: alpha profile email
  azp: spiffe://ryno.local/ryno/sandbox/<sandbox-id>
  client_id: spiffe://ryno.local/ryno/sandbox/<sandbox-id>
```

## Cleanup

The script deletes demo containers and the sandbox on exit unless you set
`KEEP_DEMO=1` or `KEEP_SANDBOX=1`.

Manual cleanup:

```shell
ryno --gateway "$GATEWAY_NAME" --gateway-endpoint "$GATEWAY_ENDPOINT" \
  sandbox delete spiffe-podman-demo

podman rm -f \
  ryno-spiffe-demo-token-issuer \
  ryno-spiffe-demo-alpha \
  ryno-spiffe-demo-beta \
  ryno-spiffe-demo-spire-oidc \
  ryno-spiffe-demo-spire-agent \
  ryno-spiffe-demo-spire-server
```
