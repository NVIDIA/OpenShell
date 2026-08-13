# Architecture

This page explains how the OpenShell Go SDK is structured internally. Understanding the design helps you navigate the API surface and write idiomatic code.

## Client Hierarchy

The SDK follows the Kubernetes client-go sub-client pattern. A single `Client` provides typed accessors for each API domain:

```text
Client
├── Sandboxes()   → SandboxInterface
├── Exec()        → ExecInterface
├── Providers()   → ProviderInterface
│   ├── Profiles()  → ProfileInterface
│   └── Refresh()   → RefreshInterface
├── Services()    → ServiceInterface
├── Files()       → FileInterface
├── Health()      → HealthInterface
├── SSH()         → SSHInterface
├── TCP()         → TCPInterface
├── Config()      → ConfigInterface
└── Policy()      → PolicyInterface
```

Each accessor returns an interface. You work with the interface, not the concrete implementation. This makes the sub-clients easy to mock and test.

## Creating a Client

All interaction starts with `NewClient`:

```go
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken("my-token"),
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

The `Config` struct controls:

| Field | Purpose |
|-------|---------|
| `Address` | Gateway host and port |
| `Auth` | Authentication provider (`StaticToken`, `NoAuth`, or custom) |
| `TLS` | TLS settings (CA cert, skip verify, client certs) |
| `Retry` | Retry policy for transient failures |

## Proto Isolation

The SDK never exposes protobuf-generated types in its public API. Instead, it defines its own Go types (in `openshell/v1/`) and converts to/from proto at the gRPC boundary.

This means:

- Your code imports `openshell/v1`, not `proto/openshellv1`
- You work with plain Go structs, not proto messages
- Proto schema changes in upstream OpenShell do not break your code (the SDK adapts internally)
- You can use standard Go patterns (json.Marshal, fmt.Sprintf, reflect) on SDK types without proto constraints

The conversion layer lives in `openshell/v1/internal/converter/` and is not part of the public API.

## Sub-Client Pattern

Each sub-client groups methods for a specific API domain. For example, `SandboxInterface` provides `Create`, `Get`, `List`, `Delete`, `WaitReady`, `Watch`, and more.

Sub-clients are cheap to access. They are created once when the `Client` is initialized and reuse the same underlying gRPC connection:

```go
// These return the same sub-client instance every time
sandboxes := client.Sandboxes()
exec := client.Exec()
```

Some sub-clients have their own sub-clients. `ProviderInterface` exposes `Profiles()` and `Refresh()`:

```go
profiles, err := client.Providers().Profiles().List(ctx, "default")
status, err := client.Providers().Refresh().GetStatus(ctx, "default", "openai", "api-key")
```

## gRPC Layer

Underneath, the SDK communicates with the OpenShell gateway over gRPC. The single `OpenShell` service in `proto/openshell.proto` defines all RPCs. The SDK maps each interface method to one or more RPCs:

| Pattern | Example |
|---------|---------|
| Unary RPC | `Create`, `Get`, `Delete` |
| Server-streaming RPC | `Watch`, `Stream`, `GetLogs` |
| Client-streaming RPC | File uploads |
| Bidirectional streaming | `Interactive`, `Forward` |

The gRPC connection is managed by the `Client`. Calling `client.Close()` cleanly shuts down all active streams and the underlying connection.

## Error Model

All SDK methods return standard Go errors. Errors from the gateway carry a `StatusError` with a typed error code. Use the `Is*` functions to classify errors:

```go
_, err := client.Sandboxes().Get(ctx, "default", "missing")
if v1.IsNotFound(err) {
    // sandbox does not exist
}
```

See the [Error Handling](error-handling.md) guide for the complete list of error checks and retry patterns.

## Fake Client

For testing, the SDK provides `openshell/v1/fake` with an in-memory implementation of `ClientInterface`. The fake client supports fixture seeding, watch events, and health simulation:

```go
fc := fake.NewClient()
fc.AddSandbox(&v1.Sandbox{Name: "test-sb", Status: v1.SandboxStatus{Phase: v1.SandboxReady}})
```

See the [Testing](testing.md) guide for complete examples.
