# OIDC Local Testing Guide

Step-by-step instructions for testing OIDC/Keycloak authentication locally,
including both standalone server testing and full end-to-end K3s testing.

## Prerequisites

- Docker or Podman
- Rust toolchain (edition 2024, rust 1.88+)
- `grpcurl` (for raw gRPC testing)
- `jq` (for JSON parsing)

## 1. Start Keycloak

```bash
mise run keycloak
```

Wait for "Keycloak is ready." The script prints connection info including test users.

Verify:

```bash
curl -s http://localhost:8180/realms/openshell/.well-known/openid-configuration | jq .issuer
# Expected: "http://localhost:8180/realms/openshell"
```

## 2. Standalone Server Testing (No K3s)

Start the server directly with OIDC enabled. No Kubernetes cluster required.

```bash
cargo run -p openshell-server -- \
  --disable-tls \
  --db-url sqlite:/tmp/openshell-test.db \
  --ssh-handshake-secret test \
  --oidc-issuer http://localhost:8180/realms/openshell
```

You should see:

```
OIDC JWT validation enabled (issuer: http://localhost:8180/realms/openshell)
Server listening address=0.0.0.0:8080
```

K8s compute driver warnings are expected and non-fatal.

### 2a. Test Health (unauthenticated — should succeed)

```bash
grpcurl -plaintext -import-path proto -proto openshell.proto \
  127.0.0.1:8080 openshell.v1.OpenShell/Health
# Expected: SERVICE_STATUS_HEALTHY
```

### 2b. Test without token (should fail)

```bash
grpcurl -plaintext -import-path proto -proto openshell.proto \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: Code: Unauthenticated, Message: missing authorization header
```

### 2c. Get tokens from Keycloak

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  | jq -r .access_token)

USER_TOKEN=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=user@test&password=user' \
  | jq -r .access_token)
```

### 2d. Test authenticated access

```bash
# Admin can list sandboxes
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: {} (empty list)

# User can list sandboxes
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $USER_TOKEN" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: {} (empty list)
```

### 2e. Test RBAC

```bash
# User CANNOT create provider (requires openshell-admin)
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $USER_TOKEN" \
  -d '{"provider":{"name":"test","type":"claude","credentials":{"key":"val"}}}' \
  127.0.0.1:8080 openshell.v1.OpenShell/CreateProvider
# Expected: Code: PermissionDenied, Message: role 'openshell-admin' required

# Admin CAN create provider
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"provider":{"name":"test","type":"claude","credentials":{"key":"val"}}}' \
  127.0.0.1:8080 openshell.v1.OpenShell/CreateProvider
# Expected: success
```

### 2f. Test sandbox secret auth

```bash
# Correct secret — should succeed (returns an empty bundle when no routes are configured)
grpcurl -plaintext -import-path proto -proto inference.proto \
  -H "x-sandbox-secret: test" \
  127.0.0.1:8080 openshell.inference.v1.Inference/GetInferenceBundle
# Expected: success with { "routes": [], ... }

# Wrong secret — should fail at auth
grpcurl -plaintext -import-path proto -proto inference.proto \
  -H "x-sandbox-secret: wrong" \
  127.0.0.1:8080 openshell.inference.v1.Inference/GetInferenceBundle
# Expected: Code: Unauthenticated, Message: invalid sandbox secret

# No secret — should fail at auth
grpcurl -plaintext -import-path proto -proto inference.proto \
  127.0.0.1:8080 openshell.inference.v1.Inference/GetInferenceBundle
# Expected: Code: Unauthenticated, Message: sandbox secret required
```

### 2g. Test OIDC discovery endpoint

```bash
curl -s http://127.0.0.1:8080/auth/oidc-config | jq .
# Expected: {"audience":"openshell-cli","issuer":"http://localhost:8180/realms/openshell"}
```

Stop the standalone server (Ctrl+C) before proceeding to K3s testing.

## 3. CLI OIDC Flow (Standalone)

With the standalone server running from step 2:

```bash
# Register the gateway with OIDC auth
cargo run -p openshell-cli --features bundled-z3 -- gateway add http://127.0.0.1:8080 \
  --oidc-issuer http://localhost:8180/realms/openshell

# Browser opens to Keycloak. Login with: admin@test / admin
# Expected: ✓ Authenticated to gateway 'localhost' as admin@test

# Verify stored token
cat ~/.config/openshell/gateways/127.0.0.1/oidc_token.json | jq .

# Test authenticated CLI command
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
```

### Test client credentials (CI mode)

The CI client (`openshell-ci`) is separate from the interactive client (`openshell-cli`).
Register the gateway with the CI client ID first:

```bash
cargo run -p openshell-cli --features bundled-z3 -- gateway add http://127.0.0.1:8080 \
  --oidc-issuer http://localhost:8180/realms/openshell \
  --oidc-client-id openshell-ci

OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret \
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Expected: ✓ Authenticated to gateway (no browser opened)
```

### Test logout

```bash
cargo run -p openshell-cli --features bundled-z3 -- gateway logout
# Expected: ✓ Logged out of gateway

cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: error (no token)
```

## 4. End-to-End K3s Testing

This deploys a full K3s cluster with OIDC enforcement and tests sandbox
creation, RBAC, login/logout, and token expiry.

### 4a. Bootstrap the cluster with OIDC

Keycloak runs on the host. The K3s container reaches it via the host IP.
The `OPENSHELL_OIDC_ISSUER` env var tells the deploy script to pass the
issuer to the Helm chart so the gateway starts with JWT validation enabled.

```bash
HOST_IP=$(hostname -I | awk '{print $1}')
OPENSHELL_OIDC_ISSUER="http://${HOST_IP}:8180/realms/openshell" \
OPENSHELL_OIDC_SCOPES="openshell:all" \
mise run cluster
```

Add `OPENSHELL_OIDC_SCOPES_CLAIM="scope"` to also enable scope enforcement.
The `OPENSHELL_OIDC_SCOPES` value is stored in gateway metadata so `gateway login`
requests these scopes automatically.

Wait for "Deploy complete!" and verify OIDC is active:

```bash
CONTAINER=$(docker ps --format '{{.Names}}' | grep openshell-cluster)
docker exec $CONTAINER kubectl -n openshell logs openshell-0 | grep OIDC
# Expected: OIDC JWT validation enabled (issuer: http://...)
```

### 4b. Login to the gateway

The bootstrap step above configures the gateway metadata with the OIDC
issuer automatically. Authenticate with Keycloak:

```bash
openshell gateway login
# Login with: admin@test / admin
# Expected: ✓ Authenticated to gateway 'openshell' as admin@test
```

### 4c. Create and list sandboxes

```bash
# Login as admin
openshell gateway login
# Login with: admin@test / admin
# Expected: ✓ Authenticated to gateway 'openshell' as admin@test

# Create a sandbox
openshell sandbox create
# Expected: Created sandbox: <name>

# List sandboxes
openshell sandbox list
# Expected: shows the created sandbox
```

### 4d. Verify authentication enforcement

```bash
# Logout
openshell gateway logout
# Expected: ✓ Logged out of gateway 'openshell'

# Should fail without token
openshell sandbox list
# Expected: Unauthenticated error

# Login again
openshell gateway login
# Login with: admin@test / admin

# Should work again
openshell sandbox list
# Expected: shows sandboxes
```

### 4e. Verify token expiry

Keycloak access tokens expire after 5 minutes by default.

```bash
# Wait 5+ minutes, then:
openshell sandbox list
# Expected: Unauthenticated: ExpiredSignature

# Re-login
openshell gateway login
openshell sandbox list
# Expected: success
```

### 4f. Verify RBAC

```bash
# Login as admin
openshell gateway login
# Login with: admin@test / admin

# Admin can create a provider
openshell provider create \
  --name test-provider --type claude --credential API_KEY=test123
# Expected: success

# Login as user (openshell-user only, no openshell-admin)
openshell gateway login
# Login with: user@test / user
# Expected: ✓ Authenticated to gateway 'openshell' as user@test

# User can list sandboxes
openshell sandbox list
# Expected: success

# User can list providers
openshell provider list
# Expected: shows test-provider

# User CANNOT create a provider
openshell provider create \
  --name blocked --type claude --credential API_KEY=nope
# Expected: PermissionDenied: role 'openshell-admin' required

# User CANNOT delete a provider
openshell provider delete test-provider
# Expected: PermissionDenied: role 'openshell-admin' required

# User CAN create sandboxes
openshell sandbox create
# Expected: success
```

### 4g. Test client credentials (CI mode)

The CI client uses `openshell-ci` (confidential) instead of `openshell-cli` (public).
Update the gateway metadata to use the CI client, then login:

```bash
jq '.oidc_client_id = "openshell-ci"' \
  ~/.config/openshell/gateways/openshell/metadata.json > /tmp/meta.json \
  && mv /tmp/meta.json ~/.config/openshell/gateways/openshell/metadata.json

OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret \
openshell gateway login
# Expected: ✓ Authenticated to gateway 'openshell' (no browser)

openshell sandbox list
# Expected: success

# Restore interactive client for further testing
jq '.oidc_client_id = "openshell-cli"' \
  ~/.config/openshell/gateways/openshell/metadata.json > /tmp/meta.json \
  && mv /tmp/meta.json ~/.config/openshell/gateways/openshell/metadata.json
```

### 4h. Clean up sandboxes

```bash
# Login as admin to clean up
openshell gateway login
# Login with: admin@test / admin

openshell sandbox list
# Note sandbox names, then:
openshell sandbox delete <name>

openshell provider delete test-provider
```

## 5. Scope-Based Permissions Testing

Scopes provide fine-grained, per-method access control on top of roles. This section tests scope enforcement using both the standalone server and K3s.

### 5a. Standalone server with scope enforcement

```bash
cargo run -p openshell-server -- \
  --disable-tls \
  --db-url sqlite:/tmp/openshell-scopes-test.db \
  --ssh-handshake-secret test \
  --oidc-issuer http://localhost:8180/realms/openshell \
  --oidc-scopes-claim scope
```

### 5b. Get tokens with specific scopes

```bash
# Token with sandbox scopes only
TOKEN_SANDBOX=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  -d 'scope=openid sandbox:read sandbox:write' \
  | jq -r .access_token)

# Token with all scopes
TOKEN_ALL=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  -d 'scope=openid openshell:all' \
  | jq -r .access_token)

# Token without OpenShell scopes (roles-only)
TOKEN_NO_SCOPES=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  | jq -r .access_token)
```

### 5c. Inspect tokens

```bash
# Verify scopes are in the JWT
echo "$TOKEN_SANDBOX" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{scope, realm_access, preferred_username}'
# Expected: scope contains "sandbox:read sandbox:write", realm_access has roles, preferred_username is set

echo "$TOKEN_NO_SCOPES" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.scope'
# Expected: "openid email profile" (no OpenShell scopes)
```

### 5d. Test scope enforcement with grpcurl

```bash
# Sandbox-scoped token — ListSandboxes should work
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN_SANDBOX" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: success (empty list)

# Sandbox-scoped token — ListProviders should FAIL
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN_SANDBOX" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListProviders
# Expected: PermissionDenied: scope 'provider:read' required

# openshell:all token — everything works
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN_ALL" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListProviders
# Expected: success

# No-scopes token — denied
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN_NO_SCOPES" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: PermissionDenied: scope 'sandbox:read' required
```

### 5e. Test CLI with scopes

Stop the standalone server. Register a gateway with scopes:

```bash
openshell gateway add http://127.0.0.1:8080 \
  --oidc-issuer http://localhost:8180/realms/openshell \
  --oidc-scopes "sandbox:read sandbox:write"
```

Or for K3s testing, pass `OPENSHELL_OIDC_SCOPES` during bootstrap:

```bash
HOST_IP=$(hostname -I | awk '{print $1}')
OPENSHELL_OIDC_ISSUER="http://${HOST_IP}:8180/realms/openshell" \
OPENSHELL_OIDC_SCOPES_CLAIM="scope" \
OPENSHELL_OIDC_SCOPES="sandbox:read sandbox:write" \
mise run cluster
```

Then login and test:

```bash
openshell gateway login
# Login with: admin@test / admin

openshell sandbox list    # should work (has sandbox:read)
openshell provider list   # should fail (no provider:read scope)
```

### 5f. Test openshell:all via CLI

For K3s, restart the cluster with `openshell:all`:

```bash
mise run cluster:stop
HOST_IP=$(hostname -I | awk '{print $1}')
OPENSHELL_OIDC_ISSUER="http://${HOST_IP}:8180/realms/openshell" \
OPENSHELL_OIDC_SCOPES_CLAIM="scope" \
OPENSHELL_OIDC_SCOPES="openshell:all" \
mise run cluster

openshell gateway login
openshell sandbox list    # should work
openshell provider list   # should work
```

### 5g. Test CI client credentials with scopes

```bash
OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret openshell gateway login
# openshell-ci has openshell:all as a default scope

openshell sandbox list    # should work
openshell provider list   # should work
```

### 5h. Test without scope enforcement (default behavior preserved)

Restart the server WITHOUT `--oidc-scopes-claim`:

```bash
cargo run -p openshell-server -- \
  --disable-tls \
  --db-url sqlite:/tmp/openshell-noscopes-test.db \
  --ssh-handshake-secret test \
  --oidc-issuer http://localhost:8180/realms/openshell
```

```bash
# Token without scopes should work (roles-only mode)
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN_NO_SCOPES" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: success — scopes are not enforced
```

## 6. Cleanup

```bash
# Stop the cluster
mise run cluster:stop

# Stop Keycloak
mise run keycloak:stop
```

## Test Users

| Username | Password | Roles |
|---|---|---|
| `admin@test` | `admin` | `openshell-admin`, `openshell-user` |
| `user@test` | `user` | `openshell-user` |

## OIDC Clients

| Client ID | Type | Grant | Secret |
|---|---|---|---|
| `openshell-cli` | Public | Auth Code + PKCE | N/A |
| `openshell-ci` | Confidential | Client Credentials | `ci-test-secret` |

## Method Authentication Categories

| Category | Methods | Auth Mechanism |
|---|---|---|
| Unauthenticated | Health, gRPC reflection | None |
| Sandbox-secret | GetSandboxConfig, GetSandboxProviderEnvironment, ReportPolicyStatus, PushSandboxLogs, SubmitPolicyAnalysis | `x-sandbox-secret` header |
| Dual-auth | UpdateConfig | Bearer token OR `x-sandbox-secret` |
| OIDC Bearer | All other RPCs | `authorization: Bearer <JWT>` |

## Role Requirements

| Operation | Required Role |
|---|---|
| Sandbox create, list, delete, exec, SSH | `openshell-user` |
| Provider list, get | `openshell-user` |
| Provider create, update, delete | `openshell-admin` |
| Global config/policy updates | `openshell-admin` |
| Draft policy approvals | `openshell-admin` |

## Troubleshooting

**"missing authorization header"** — No OIDC token stored. Run `openshell gateway login`.

**"invalid token: ExpiredSignature"** — Token expired (default 5 min). Run `openshell gateway login`.

**"PermissionDenied: role 'openshell-admin' required"** — Logged in as a user without the admin role. Login as `admin@test`.

**"sandbox secret required for this method"** — A sandbox-to-server RPC was called without the `x-sandbox-secret` header.

**"OIDC discovery request failed"** — Server can't reach Keycloak. Use the host IP (not `localhost`) for K3s deployments.

**"invalid token: unknown signing key"** — JWKS key mismatch. Restart the server to refresh the cache.

**No "OIDC JWT validation enabled" in K3s logs** — The `OPENSHELL_OIDC_ISSUER` env var was not set when deploying. Re-run `OPENSHELL_OIDC_ISSUER="http://<HOST_IP>:8180/realms/openshell" mise run cluster gateway` to rebuild and redeploy with OIDC enabled.

**"InvalidIssuer"** — The issuer URL in the OIDC token does not match the server's configured issuer. Ensure the gateway metadata `oidc_issuer` uses the same URL the server was started with (typically the host IP, not `localhost`).

**"connection refused" with grpcurl** — On Fedora/systems where `localhost` resolves to IPv6, use `127.0.0.1` instead of `localhost`.

**"no such table: objects"** — Using `sqlite::memory:` which doesn't run migrations. Use a file path like `sqlite:/tmp/openshell-test.db`.

**"scope 'X' required"** — The server has `--oidc-scopes-claim` enabled and the token is missing the required scope. Either request the scope during login (`--oidc-scopes "sandbox:read sandbox:write"`) or use `openshell:all` for full access.

**Token has scopes but server doesn't enforce them** — The server was started without `--oidc-scopes-claim`. Add `--oidc-scopes-claim scope` (for Keycloak) to enable enforcement.

**Scopes missing from token after Keycloak login** — The browser may have reused an old Keycloak session with the previous scope set. Sign out at `http://localhost:8180/realms/openshell/account/#/` and re-run `openshell gateway login`.
