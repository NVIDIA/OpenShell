# Testing

The SDK ships a `fake` package that provides an in-memory implementation of all client interfaces. Use it in your test suites to exercise SDK interactions without a real gateway.

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"
```

The fake client follows the same pattern as `k8s.io/client-go/kubernetes/fake`: it maintains in-memory stores, supports watch event broadcasting, and returns the same `StatusError` codes as the real client.

## Creating a Fake Client

```go
func TestMyOperator(t *testing.T) {
    client := fake.NewClient()
    defer client.Close()

    ctx := context.Background()

    // Use client exactly like the real SDK
    sb, err := client.Sandboxes().Create(ctx, "default", "test-sandbox", &v1.SandboxSpec{}, nil)
    require.NoError(t, err)
    assert.Equal(t, "Provisioning", string(sb.Status.Phase))
}
```

The returned `*fake.Client` satisfies `v1.ClientInterface`, so you can pass it anywhere your code accepts the interface.

## Fixture Seeding

Pre-populate the fake client with existing resources before your test runs. Seeded resources are available immediately via `Get` and `List` without going through `Create`.

### AddSandbox

```go
client := fake.NewClient()

// Pre-seed a sandbox that already exists
client.AddSandbox(&types.Sandbox{
    Name: "existing-sandbox",
    Status: types.SandboxStatus{
        Phase: types.SandboxReady,
    },
    ResourceVersion: 5,
})

// Now Get returns it immediately
sb, err := client.Sandboxes().Get(ctx, "default", "existing-sandbox")
// sb.Status.Phase == "Ready"
```

### AddProvider

```go
client := fake.NewClient()

// Pre-seed a provider
client.AddProvider(&types.Provider{
    Name: "my-openai",
    Type: "openai",
    Spec: types.ProviderSpec{
        Credentials: map[string]string{
            "api_key": "sk-test-key",
        },
    },
})

// List returns the seeded provider
providers, _ := client.Providers().List(ctx, "default")
// len(providers) == 1
```

## Sandbox Lifecycle

The fake client implements the full sandbox lifecycle. Created sandboxes start in the `Provisioning` phase. Calling `WaitReady` transitions them to `Ready` synchronously.

```go
client := fake.NewClient()
ctx := context.Background()

// Create starts in Provisioning
sb, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
assert.Equal(t, types.SandboxProvisioning, sb.Status.Phase)

// WaitReady transitions to Ready (synchronous in fake)
sb, err = client.Sandboxes().WaitReady(ctx, "default", "my-sandbox")
assert.Equal(t, types.SandboxReady, sb.Status.Phase)

// Delete removes the sandbox
err = client.Sandboxes().Delete(ctx, "default", "my-sandbox")
assert.NoError(t, err)

// Get after delete returns NotFound
_, err = client.Sandboxes().Get(ctx, "default", "my-sandbox")
assert.True(t, v1.IsNotFound(err))
```

## Watch Events

The fake client broadcasts watch events when resources change. Use watchers to test event-driven code.

```go
client := fake.NewClient()
ctx := context.Background()

// Start watching before making changes
watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox")
require.NoError(t, err)
defer watcher.Stop()

// Create a sandbox — triggers an ADDED event
client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)

// Read the event from the channel
event := <-watcher.ResultChan()
assert.Equal(t, types.EventAdded, event.Type)
assert.Equal(t, "my-sandbox", event.Object.Name)
```

### StopOnTerminal

Setting `StopOnTerminal: true` causes the watcher to close automatically when the sandbox reaches a terminal phase (`Ready` or `Error`).

```go
watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox", v1.WatchOptions{
    StopOnTerminal: true,
})
require.NoError(t, err)

// Create and transition to Ready
client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
client.Sandboxes().WaitReady(ctx, "default", "my-sandbox")

// Drain events — channel closes after the Ready event
var events []types.Event[*types.Sandbox]
for ev := range watcher.ResultChan() {
    events = append(events, ev)
}
// Channel is now closed
```

## Health Simulation

Use `WithHealthResult` to simulate an unhealthy or degraded gateway.

```go
// Default: healthy gateway
client := fake.NewClient()
result, _ := client.Health().Check(ctx)
// result.Healthy == true, result.Version == "fake"

// Simulate unhealthy gateway
client = fake.NewClient(fake.WithHealthResult(&types.HealthResult{
    Healthy: false,
    Version: "1.2.3",
}))
result, _ = client.Health().Check(ctx)
// result.Healthy == false
```

## Error Behavior

The fake client returns the same `StatusError` codes as the real client:

| Scenario | Error Code |
|----------|------------|
| `Get` for a non-existent resource | `ErrorNotFound` |
| `Create` with a duplicate name | `ErrorAlreadyExists` |
| Any call after `Close()` | `ErrorUnavailable` |
| Unimplemented operations (e.g., `GetLogs`) | `ErrorUnimplemented` |

```go
client := fake.NewClient()
client.Close()

_, err := client.Sandboxes().Get(ctx, "default", "anything")
assert.True(t, v1.IsUnavailable(err))
```

## Concurrency

All fake client operations are safe for concurrent use. The internal stores use mutex-based synchronization. This means you can safely use the fake client from multiple goroutines in parallel tests.

See also: [Error Handling](error-handling.md), [API Reference](api/overview.md)
