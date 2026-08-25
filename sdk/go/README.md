# OpenShell SDK for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/NVIDIA/OpenShell/sdk/go.svg)](https://pkg.go.dev/github.com/NVIDIA/OpenShell/sdk/go)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)

> [!IMPORTANT]
> **[Read the full documentation](https://ro14nd.de/openshell-sdk-go/)** for guides, API reference with gRPC mapping, and testing patterns.

A Go SDK for interacting with [OpenShell](https://github.com/NVIDIA/OpenShell)
servers, providing idiomatic Go bindings for shell session management, command
execution, provider configuration, and service exposure.

## Why a Go SDK?

Go is the language of the Kubernetes ecosystem. If you want to build an
operator, controller, or any automation that manages OpenShell resources as
native Kubernetes objects, you need a Go client.

This SDK is modeled after
[`k8s.io/client-go`](https://github.com/kubernetes/client-go), the standard
Kubernetes client library that every Go operator developer already knows. The
patterns will look familiar:

- **Typed sub-clients per resource**: `client.Sandboxes()`, `client.Providers()`,
  `client.Exec()`, just like `clientset.CoreV1().Pods()`
- **Domain types separated from wire formats**: clean Go structs in a `types`
  package, no proto leakage into the public API (like `k8s.io/api`)
- **Watch primitives**: channel-based watchers with `ResultChan()` and `Stop()`,
  identical to `watch.Interface` in client-go
- **Functional options**: variadic option patterns for list filtering,
  pagination, and watch configuration
- **Composable auth with token refresh**: wraps `oauth2.TokenSource` for
  automatic token caching and coalesced refresh, following the k8s client-go
  `cachingTokenSource` pattern
- **Fake client for testing**: an in-memory implementation of the full client
  interface (like `k8s.io/client-go/kubernetes/fake`), so operators can be tested
  without a real gateway

## Quick Start

```go
import v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

// Connect to a gateway
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken("my-token"),
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Create a sandbox and wait until it's ready
sandbox, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{
    Template: &v1.SandboxTemplate{Image: "python:3.12"},
}, nil)
if err != nil {
    log.Fatal(err)
}
sandbox, err = client.Sandboxes().WaitReady(ctx, "default", sandbox.Name)
if err != nil {
    log.Fatal(err)
}

// Run a command
result, err := client.Exec().Run(ctx, "default", sandbox.Name,
    []string{"python3", "-c", "print('hello from sandbox')"},
    v1.ExecOptions{},
)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(result.Stdout))
```

### With automatic token refresh

For OIDC gateways, use `RefreshableToken` to wrap any `oauth2.TokenSource` with
automatic caching and coalesced refresh:

```go
import "golang.org/x/oauth2"

tokenSource := oauth2Config.TokenSource(ctx, initialToken)
auth, err := v1.RefreshableToken(tokenSource,
    v1.WithLeeway(30*time.Second),
)
if err != nil {
    log.Fatal(err)
}
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    auth,
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

Concurrent callers share a single refresh call. If the token source fails, the
SDK falls back to the cached token with a logged warning. See the
[Auth](https://ro14nd.de/openshell-sdk-go/api/auth.html) docs for details.

### With edge proxy headers

When a gateway sits behind a zero-trust reverse proxy, use `WithExtraHeaders` to
attach proxy-specific headers alongside standard auth:

```go
base := v1.StaticToken("my-gateway-token")
auth, err := v1.WithExtraHeaders(base, map[string]string{
    "x-proxy-auth": "proxy-secret",
})
if err != nil {
    log.Fatal(err)
}
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    auth,
})
```

For Cloudflare Access, use the convenience constructor in the `edge` package:

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/edge"

auth, err := edge.CloudflareAccess(base, os.Getenv("CF_ACCESS_TOKEN"))
```

For gRPC behind edge proxies that reject HTTP/2, use the WebSocket tunnel:

```go
tunnel, err := edge.NewTunnelProxy(
    "wss://gateway.example.com/ws",
    os.Getenv("CF_ACCESS_TOKEN"),
)
if err != nil {
    log.Fatal(err)
}
defer tunnel.Close()

client, err := v1.NewClient(v1.Config{
    Address: tunnel.Addr(),
    Auth:    v1.StaticToken("my-token"),
    TLS:     &v1.TLSConfig{Insecure: true}, // local tunnel, no TLS
})
```

### OIDC Login

The `oidc` package provides gateway-aware OIDC authentication with browser,
keyboard, device code, and client credentials flows:

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/oidc"

// Gateway-aware login: reads OIDC config from gateway metadata
token, err := oidc.Login(ctx, "my-gateway")
if err != nil {
    log.Fatal(err)
}

// Use the token with the SDK client
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken(token.AccessToken),
})
```

For headless environments, use the device code flow:

```go
token, err := oidc.DeviceLogin(ctx,
    oidc.WithIssuer("https://auth.example.com"),
    oidc.WithClientID("my-app"),
)
```

For a one-shot service-account token exchange, use `ClientCredentials`. For a
long-running SDK client, attach the renewable, memory-only auth provider:

```go
auth, err := oidc.NewClientCredentialsAuth(
    oidc.WithGateway("my-gateway"),
    oidc.WithClientSecretProvider(func(context.Context) (string, error) {
        return os.Getenv("OPENSHELL_OIDC_CLIENT_SECRET"), nil
    }),
)
if err != nil {
    log.Fatal(err)
}

client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    auth,
    TLS:     tlsConfig,
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

You can use explicit `WithIssuer`, `WithClientID`, `WithScopes`, and
`WithAudience` options instead of `WithGateway`. The provider repeats the grant
before expiry and never writes the secret or access token to disk.

See the [oidc package docs](https://pkg.go.dev/github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/oidc) for all options and flows.

See the [Getting Started](https://ro14nd.de/openshell-sdk-go/getting-started.html) guide for the full walkthrough.

## Migrating from v0.0.101

The pre-1.0 SDK intentionally includes source-incompatible API corrections:

- `TCP.Listen` returns a `ForwardListener` lifecycle handle. The SDK owns the
  accept loop; callers dial `Addr()` and call `Close()` instead of calling
  `Accept()` or passing the handle to `http.Serve`.
- Resource operations take an explicit workspace, and workspace-bearing domain
  types preserve that scope.
- Several public struct field orders changed. Use keyed struct literals.
- Initialisms use Go spelling, including `JSONRPCMaxBodyBytes`.

These changes are intentional while the module remains below v1. Update callers
as one migration rather than relying on the v0.0.101 API shape.

### Inference Route Management

Configure how inference requests are routed for a workspace:

```go
// Set an inference route
route, err := client.Inference().SetRoute(ctx, "my-workspace", &v1.InferenceRouteConfig{
    ProviderName: "openai",
    ModelID:      "gpt-4",
    RouteName:    "",        // empty string = default route
    TimeoutSecs:  120,
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Route v%d: %s/%s\n", route.Version, route.ProviderName, route.ModelID)

// Retrieve the route
route, err = client.Inference().GetRoute(ctx, "my-workspace", "")
if err != nil {
    log.Fatal(err)
}

// Delete the route
err = client.Inference().DeleteRoute(ctx, "my-workspace", "")
if err != nil {
    log.Fatal(err)
}
```

## Architecture

```
Client
  ├── Sandboxes()   → SandboxInterface    (create, get, list, delete, watch, wait, logs)
  ├── Exec()        → ExecInterface       (run, stream, interactive)
  ├── Files()       → FileInterface       (upload, download)
  ├── Health()      → HealthInterface     (health check, gateway info, current user)
  ├── Services()    → ServiceInterface    (expose, get, list, delete)
  ├── Providers()   → ProviderInterface   (CRUD + ensure)
  │     ├── Profiles() → ProfileInterface (list, get, import, update, lint, delete)
  │     └── Refresh()  → RefreshInterface (configure, status, rotate, delete)
  ├── Workspaces()  → WorkspaceInterface  (create, get, list, delete, members)
  ├── Inference()   → InferenceInterface  (set, get, delete inference routes)
  └── Policy()      → PolicyInterface     (draft review, approve, reject, merge, status)
```

All domain types live in `openshell/v1/types/`. Proto-to-Go conversions happen in
an internal converter layer. The public API surface uses type aliases so
consumers import a single package. See the [Architecture](https://ro14nd.de/openshell-sdk-go/architecture.html) overview for details.

## Features

| Feature | Interface | Docs |
|---------|-----------|------|
| Sandbox lifecycle (create, get, list, delete, watch, wait) | `SandboxInterface` | [Sandboxes](https://ro14nd.de/openshell-sdk-go/api/sandboxes.html) |
| Command execution (collected, streamed, interactive PTY) | `ExecInterface` | [Exec](https://ro14nd.de/openshell-sdk-go/api/exec.html) |
| Provider management (CRUD + idempotent ensure) | `ProviderInterface` | [Providers](https://ro14nd.de/openshell-sdk-go/api/providers.html) |
| Provider profiles (list, import, lint, update) | `ProfileInterface` | [Profiles](https://ro14nd.de/openshell-sdk-go/api/profiles.html) |
| Credential refresh (configure, rotate, status) | `RefreshInterface` | [Refresh](https://ro14nd.de/openshell-sdk-go/api/refresh.html) |
| Service exposure (expose, list, delete) | `ServiceInterface` | [Services](https://ro14nd.de/openshell-sdk-go/api/services.html) |
| File transfer API (transport capability-gated) | `FileInterface` | [Files](https://ro14nd.de/openshell-sdk-go/api/files.html) |
| Policy management (draft review, approve, reject, merge, global policy) | `PolicyInterface` | [Policy](https://ro14nd.de/openshell-sdk-go/api/policy.html) |
| Sandbox logs (streaming retrieval) | `SandboxInterface` | [Sandboxes](https://ro14nd.de/openshell-sdk-go/api/sandboxes.html) |
| Workspace management (create, get, list, delete, members) | `WorkspaceInterface` | [Workspaces](https://ro14nd.de/openshell-sdk-go/api/workspaces.html) |
| Inference route management (set, get, delete) | `InferenceInterface` | [Inference](https://ro14nd.de/openshell-sdk-go/api/inference.html) |
| Gateway info and current user identity | `HealthInterface` | [Health](https://ro14nd.de/openshell-sdk-go/api/health.html) |
| Health checking | `HealthInterface` | [Health](https://ro14nd.de/openshell-sdk-go/api/health.html) |
| SSH tunneling and TCP forwarding | `SSHInterface`, `TCPInterface` | [SSH](https://ro14nd.de/openshell-sdk-go/api/ssh.html), [TCP](https://ro14nd.de/openshell-sdk-go/api/tcp.html) |
| Auth: static token, refreshable token (oauth2.TokenSource) | `AuthProvider` | [Auth](https://ro14nd.de/openshell-sdk-go/api/auth.html) |
| Edge auth: extra headers, Cloudflare Access, WebSocket tunnel | `AuthProvider`, `edge.TunnelProxy` | [Edge](https://ro14nd.de/openshell-sdk-go/api/edge.html) |
| Typed errors (`IsNotFound`, `IsAlreadyExists`, `IsConflict`, ...) | `StatusError` | [Error Handling](https://ro14nd.de/openshell-sdk-go/error-handling.html) |
| Real-time watch with auto-stop on terminal phase | `WatchInterface[T]` | [Sandboxes](https://ro14nd.de/openshell-sdk-go/api/sandboxes.html) |
| Fake client for testing (no gRPC server needed) | `fake.Client` | [Testing](https://ro14nd.de/openshell-sdk-go/testing.html) |
| OIDC login and renewable service auth | `oidc.Login`, `oidc.DeviceLogin`, `oidc.ClientCredentials`, `oidc.NewClientCredentialsAuth` | [OIDC](https://pkg.go.dev/github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/oidc) |
| Gateway config convenience (load CLI gateway configs, auto-wire auth) | `gateway.NewClient`, `gateway.LoadConfig` | [Gateway](https://ro14nd.de/openshell-sdk-go/api/gateway.html) |

## Prerequisites

- Go 1.25 or later
- [mise](https://mise.jdx.dev) (recommended for reproducible builds)

## Build and Test

```bash
git clone https://github.com/NVIDIA/OpenShell.git
cd OpenShell/sdk/go

mise run test    # Run tests with coverage
mise run lint    # Run golangci-lint
mise run ci      # Full CI pipeline (lint + build + test)
```

Build commands use [mise](https://mise.jdx.dev) for reproducible tool management.

## Documentation

Full API documentation is available at the [OpenShell Go SDK Docs](https://ro14nd.de/openshell-sdk-go/) site.

To build the docs locally:

```bash
cargo install mdbook
mdbook serve docs
```

## License

Apache-2.0. See [LICENSE](../../LICENSE) for details.

Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
