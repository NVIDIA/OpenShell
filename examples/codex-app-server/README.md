# Codex app server in an Ryno sandbox

This example builds a sandbox image with Codex, runs its app server inside an
Ryno sandbox, exposes the WebSocket service through the local gateway, and
connects a Codex client running on the host.

Use this example only with a local, loopback-bound Ryno gateway. The app
server does not use its own bearer-token authentication, and the exposed URL is
reachable by other local processes.

## Prerequisites

- A running local Ryno gateway backed by Docker
- `docker`, `ryno`, the latest Codex client, and `jq` on the host
- A host Codex login in `$HOME/.codex/auth.json`

Run the following commands from the example directory:

```shell
cd examples/codex-app-server
```

## 1. Build the image

This installs the latest published Codex version in the image. Keep the host
client current as well to avoid app-server protocol incompatibilities.

```shell
docker build --pull --no-cache --tag ryno/codex-app-server:local --file Dockerfile .
```

## 2. Import the provider profile

The gateway starts with an empty provider-profile catalog. Validate and import
the profile included with this example before creating the provider:

```shell
ryno provider profile lint --file codex.yaml
```

```shell
ryno provider profile import --file codex.yaml
```

## 3. Create the provider

These commands create a provider from the current host login, move the refresh
token into gateway-only refresh material, and rotate the access token once. The
sandbox receives opaque handles for only the access token and account ID; it
never receives the refresh token. Run these commands once per workspace.

```shell
ryno provider create \
  --name codex \
  --type codex \
  --credential "CODEX_AUTH_ACCESS_TOKEN=$(jq -er '.tokens.access_token' "$HOME/.codex/auth.json")" \
  --credential "CODEX_AUTH_ACCOUNT_ID=$(jq -er '.tokens.account_id' "$HOME/.codex/auth.json")"
```

```shell
env "CODEX_AUTH_REFRESH_TOKEN=$(jq -er '.tokens.refresh_token' "$HOME/.codex/auth.json")" \
  ryno provider refresh configure codex \
    --credential-key CODEX_AUTH_ACCESS_TOKEN \
    --strategy oauth2-refresh-token \
    --material client_id=app_EMoamEEZ73f0CkXaXp7hrann \
    --secret-material-env refresh_token=CODEX_AUTH_REFRESH_TOKEN
```

```shell
ryno provider refresh rotate codex \
  --credential-key CODEX_AUTH_ACCESS_TOKEN
```

## 4. Launch the sandbox

```shell
ryno sandbox create \
  --name codex-app-server \
  --from ryno/codex-app-server:local \
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
    "": "http://default--codex-app-server.ryno.localhost:<gateway-port>/"
  }
}
```

Convert the returned URL to its WebSocket scheme and connect the local client,
replacing `<gateway-port>` with the port from the create result:

```shell
codex --remote ws://default--codex-app-server.ryno.localhost:<gateway-port>/ --no-alt-screen
```

## Clean up

```shell
ryno sandbox delete codex-app-server
ryno provider delete codex
ryno provider profile delete codex
docker image rm ryno/codex-app-server:local
```
