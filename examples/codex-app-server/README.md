# Codex app server in an OpenShell sandbox

This example builds a sandbox image with Codex, runs its app server inside an
OpenShell sandbox, exposes the WebSocket service through the local gateway, and
connects a Codex client running on the host.

Use this example only with a local, loopback-bound OpenShell gateway. The app
server does not use its own bearer-token authentication, and the exposed URL is
reachable by other local processes.

## Prerequisites

- A running local OpenShell gateway backed by Docker
- `docker`, `openshell`, the latest Codex client, and `jq` on the host
- A host Codex login in `$HOME/.codex/auth.json`

Run the following commands from the example directory:

```shell
cd examples/codex-app-server
```

## 1. Build the image

This installs the latest published Codex version in the image. Keep the host
client current as well to avoid app-server protocol incompatibilities.

```shell
docker build --pull --no-cache --tag openshell/codex-app-server:local --file Dockerfile .
```

## 2. Import the provider profile

The gateway starts with an empty provider-profile catalog. Validate and import
the profile included with this example before creating the provider:

```shell
openshell provider profile lint --file codex.yaml
```

```shell
openshell provider profile import --file codex.yaml
```

## 3. Create the provider

These commands create a provider from the current host login, move the refresh
token into gateway-only refresh material, and rotate the access token once. The
sandbox receives opaque handles for only the access token and account ID; it
never receives the refresh token. Run these commands once per workspace.

```shell
openshell provider create \
  --name codex \
  --type codex \
  --credential "CODEX_AUTH_ACCESS_TOKEN=$(jq -er '.tokens.access_token' "$HOME/.codex/auth.json")" \
  --credential "CODEX_AUTH_ACCOUNT_ID=$(jq -er '.tokens.account_id' "$HOME/.codex/auth.json")"
```

```shell
env "CODEX_AUTH_REFRESH_TOKEN=$(jq -er '.tokens.refresh_token' "$HOME/.codex/auth.json")" \
  openshell provider refresh configure codex \
    --credential-key CODEX_AUTH_ACCESS_TOKEN \
    --strategy oauth2-refresh-token \
    --material client_id=app_EMoamEEZ73f0CkXaXp7hrann \
    --secret-material-env refresh_token=CODEX_AUTH_REFRESH_TOKEN
```

```shell
openshell provider refresh rotate codex \
  --credential-key CODEX_AUTH_ACCESS_TOKEN
```

## 4. Launch the sandbox

```shell
openshell sandbox create \
  --name codex-app-server \
  --from openshell/codex-app-server:local \
  --expose 4500 \
  --detach \
  --no-tty \
  --provider codex \
  --output json \
  -- start-codex-app-server
```

The create result includes the exposed endpoint:

```json
{
  "service_urls": {
    "": "http://default--codex-app-server.openshell.localhost:<gateway-port>/"
  }
}
```

Convert the returned URL to its WebSocket scheme and connect the local client,
replacing `<gateway-port>` with the port from the create result:

```shell
codex --remote ws://default--codex-app-server.openshell.localhost:<gateway-port>/ --no-alt-screen
```

## Clean up

```shell
openshell sandbox delete codex-app-server
openshell provider delete codex
openshell provider profile delete codex
docker image rm openshell/codex-app-server:local
```
