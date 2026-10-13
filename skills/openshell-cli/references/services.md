# Images, forwarding, services, and inference

Run custom images, reach services inside sandboxes, and attach inference providers.

## Bring your own container

Build a custom container image and run it as a sandbox.

### Create a sandbox from a pre-built image

```bash
docker build -t my-app:latest .
openshell sandbox create --from my-app:latest --name my-app
```

The `--from` flag accepts an explicit OCI image reference such as `myregistry.com/img:tag`. It does not expand catalog aliases. Build local Dockerfiles first with the same container engine as the local gateway, then pass the image tag.

Use `docker build -t my-app:latest` for Docker gateways. For Podman gateways, use `podman build -t localhost/my-app:latest` and pass `localhost/my-app:latest` to `--from`. For remote gateways, push the image to a registry reachable by the gateway.

For Docker and Podman gateways, custom images should declare a non-root OCI
`USER`. Images without one run as numeric UID and GID `1000`. Each explicit `process.run_as_user` or `process.run_as_group` policy
field wins independently; omitted fields fall back to the image declaration.
Explicit numeric fields may use any UID/GID from `1` through
`4294967294`; `0` is root and `4294967295` is the invalid identity sentinel.
Warn users that low IDs can inherit permissions from matching accounts, image
files, mounted volumes, or devices.

### Forward ports

```bash
# Foreground (blocks)
openshell forward start 8080 my-app

# Background (returns immediately)
openshell forward start 8080 my-app -d
```

The service is now reachable at `localhost:8080`.
CLI forwards ignore SSH multiplexing and automatic backgrounding settings in the
user's SSH config. Only background forwards are tracked by `forward list` and
managed by `forward stop`; foreground forwards end when the command exits.

Manage or iterate on the sandbox:

```bash
openshell forward list
openshell forward stop 8080 my-app
openshell sandbox delete my-app
openshell sandbox create --from my-app:latest --name my-app --forward 8080
```

Use structured output when automation needs the tracked forward metadata and
validated process state:

```bash
openshell forward list --output json
```

Each record includes `workspace`, `sandbox`, `bind_address`, `port`, `pid`, and
`alive`. The `alive` boolean validates the workspace-scoped sandbox and tracked
process identity; it does not probe the forwarded socket.

Create and forward in one command:

```bash
openshell sandbox create --from my-app:latest --forward 8080 -- ./start-server.sh
```

The `--forward` flag starts a background port forward before the command runs.

## Service access

Use `forward` for local access and `service` for a gateway-managed HTTP endpoint:

```bash
# SSH-based same-port forwarding; optional bind address is accepted.
openshell forward start 127.0.0.1:8080 my-app -d

# gRPC relay to a loopback TCP service, with an optional dynamic local port.
openshell forward service my-app --target-port 8000 --local 127.0.0.1:0

# Create a sandbox with its unnamed HTTP or WebSocket service exposed.
openshell sandbox create \
  --name my-app \
  --from my-app:latest \
  --expose 8080 \
  --expose-authorization-mode bearer-passthrough \
  --detach \
  -- ./start-server.sh

# Expose and manage an HTTP service through the gateway.
openshell service expose my-app 8080 web \
  --authorization-mode bearer-passthrough
openshell service list my-app
openshell service list my-app --output json
openshell service get my-app web
openshell service delete my-app web
```

Use `openshell service list --all-workspaces` for a Platform Admin view across
workspaces. A sandbox name and `--all-workspaces` are mutually exclusive.

`sandbox create --expose PORT` registers the unnamed endpoint in the create
request and keeps the sandbox running. Add `--output json` for automation; the
result contains a `service_urls` map whose empty key is the unnamed endpoint.
Use `openshell service expose` after creation to add or update named endpoints.

Exposed services strip `Authorization` by default. Select
`bearer-passthrough` only when the application inside the sandbox authenticates
its own clients. This mode accepts either no `Authorization` header or exactly
one non-empty Bearer credential and forwards that value unchanged. It rejects
duplicate, malformed, or non-Bearer authorization before contacting the
application. The application remains responsible for validating the token, and
the raw token reaches the sandbox process, so never log it. Service routes
bypass control-plane RPC authorization, but they still use the gateway's
existing listener, domain routing, and TLS configuration, including any client
certificate requirement. See the published
[sandbox service documentation](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md)
for the complete security contract.

Prefer loopback binds unless the user explicitly needs LAN-visible local access.

## Inference with attached providers

Inference uses the same provider attachment workflow as other credentialed
services. Import or select a profile that authorizes the provider's native
endpoint, create the provider, and attach it only to sandboxes that need it:

```bash
openshell provider profile import -f ./inference-provider.yaml
openshell provider create --name model-provider --type <profile-id> --credential <KEY>
openshell sandbox provider attach work-session model-provider --wait --timeout 30
openshell sandbox exec work-session -- <client-command>
```

The application owns the native base URL, model, request shape, and timeout.
Launch a new process after attachment readiness so it inherits the installed provider environment. Use the `debug-inference` skill for endpoint, policy, credential-binding, or migration failures.

For an ordinary static provider update, wait for the update and launch a new client process to obtain the new reference. Do not claim that readiness updates the environment of an existing process or retargets its old reference. Acknowledged detach revokes retained references and removes them from future process environments.
