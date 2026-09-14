# Fake

Package: `openshell/v1/fake`

The fake package provides an in-memory fake implementation of all SDK
client interfaces for use in consumer test suites. It follows the
`client-go/kubernetes/fake` pattern: in-memory stores, watch event
broadcasting, and matching `StatusError` codes for equivalent error
conditions (`NotFound`, `AlreadyExists`, `Unavailable`, `Unimplemented`).

## Quick Start

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"

func TestSandboxLifecycle(t *testing.T) {
    client := fake.NewClient()
    defer client.Close()

    ctx := context.Background()

    sb, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
    require.NoError(t, err)
    assert.Equal(t, types.SandboxProvisioning, sb.Status.Phase)

    sb, err = client.Sandboxes().WaitReady(ctx, "default", "my-sandbox")
    require.NoError(t, err)
    assert.Equal(t, types.SandboxReady, sb.Status.Phase)

    require.NoError(t, client.Sandboxes().Delete(ctx, "default", "my-sandbox"))
}
```

## Creating a Client

```go
func NewClient(opts ...ClientOption) *Client
```

Returns a fake client implementing `v1.ClientInterface` with all
sub-clients wired up. Default health result is healthy. Use options
to customize initial state:

```go
client := fake.NewClient(
    fake.WithHealthResult(&types.HealthResult{Healthy: false}),
    fake.WithCurrentUser(&types.CurrentUser{Subject: "test-user"}),
    fake.WithGatewayInfo(&types.GatewayInfo{Version: "1.0.0"}),
)
```

## Pre-populating State

Seed objects directly into the fake stores for test setup:

```go
client := fake.NewClient()

client.AddSandbox("default", &types.Sandbox{
    Name:   "pre-existing",
    Status: types.SandboxStatus{Phase: types.SandboxReady},
})

client.AddProvider("default", &types.Provider{
    Name: "my-provider",
    Spec: types.ProviderSpec{Type: "docker"},
})

client.AddWorkspace(&types.Workspace{Name: "staging"})
client.AddMember("staging", &types.WorkspaceMember{
    PrincipalSubject: "subject-123",
    Role:             types.WorkspaceRoleAdmin,
})
```

All `Add*` methods deep-copy their arguments; mutating the input after
insertion does not affect the stored object.

## Sub-Client Coverage

The fake client implements every interface in `v1.ClientInterface`:

| Accessor | Interface | Behavior |
|----------|-----------|----------|
| `Sandboxes()` | `SandboxInterface` | Full CRUD, Watch, WaitReady |
| `Providers()` | `ProviderInterface` | Full CRUD, Ensure |
| `Workspaces()` | `WorkspaceInterface` | Full CRUD, Members |
| `Health()` | `HealthInterface` | Configurable result |
| `Inference()` | `InferenceInterface` | Route CRUD |
| `Policy()` | `PolicyInterface` | List, GetStatus (draft ops return Unimplemented) |
| `Exec()` | `ExecInterface` | Returns Unimplemented |
| `Files()` | `FileInterface` | Returns Unimplemented |
| `Services()` | `ServiceInterface` | Returns Unimplemented |
| `SSH()` | `SSHInterface` | Input validation, then Unimplemented |
| `TCP()` | `TCPInterface` | Input validation, then Unimplemented |
| `Config()` | `ConfigInterface` | Returns Unimplemented |

## ClientOption

| Constructor | Effect |
|-------------|--------|
| `WithHealthResult(r)` | Set the health check return value |
| `WithCurrentUser(u)` | Set the current user return value |
| `WithGatewayInfo(i)` | Set the gateway info return value |

## Thread Safety

All operations are safe for concurrent use from multiple goroutines.
`Close` is idempotent and causes all subsequent operations to return
`Unavailable`.

See also: [Testing Guide](../testing.md)
