# Sandboxes

Accessor: `client.Sandboxes()`

Manage sandbox lifecycle: create, inspect, delete, attach/detach providers,
wait for readiness, watch state changes, and retrieve logs.

## Create

Creates a new sandbox with the given name, spec, and labels.

```go
sb, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{
    Template: &v1.SandboxTemplate{
        Image: "nvcr.io/nvidia/openshell:latest",
    },
    Providers: []string{"openai"},
}, map[string]string{
    "team": "platform",
})
```

Set `GPU: true` to request the active driver's default GPU assignment. Set
`GPUCount` when the sandbox needs a specific GPU count; a non-nil `GPUCount`
also implies `GPU`.

## Create From Template

Creates a new sandbox from a reusable sandbox workload template. The template
provides workload fields such as image, environment, resources, and driver
config. The create request supplies governance fields such as providers,
policy, command, and TTY.

```go
sb, err := client.CreateSandboxFromTemplate(ctx,
    "default",
    "my-sandbox",
    "gpu-kata",
    &v1.SandboxSpec{
        Providers: []string{"openai"},
        Policy:    policy,
    },
    map[string]string{"team": "platform"},
)
```

See [Sandbox Templates](sandbox-templates.md) for template CRUD.

## Get

Retrieves a sandbox by name.

```go
sb, err := client.Sandboxes().Get(ctx, "default", "my-sandbox")
fmt.Println(sb.Status.Phase) // "Ready", "Provisioning", etc.
```

## List

Lists sandboxes with optional pagination and label filtering.

```go
// List all sandboxes
sandboxes, err := client.Sandboxes().List(ctx, "default")

// With pagination and label filtering
sandboxes, err := client.Sandboxes().List(ctx, "default", v1.ListOptions{
    Limit:         10,
    Offset:        0,
    LabelSelector: "team=platform",
})
```

## Delete

Deletes a sandbox by name.

```go
err := client.Sandboxes().Delete(ctx, "default", "my-sandbox")
```

## AttachProvider

Attaches a provider to a sandbox. The `expectedResourceVersion` enables optimistic concurrency control: pass the sandbox's current `ResourceVersion` to ensure no other client has modified it since your last read.

```go
sb, _ := client.Sandboxes().Get(ctx, "default", "my-sandbox")

result, err := client.Sandboxes().AttachProvider(ctx,
    "default", "my-sandbox",
    "openai",
    sb.ResourceVersion,
)
fmt.Println(result.Attached) // true if newly attached
```

## DetachProvider

Detaches a provider from a sandbox. Uses the same optimistic concurrency pattern as `AttachProvider`.

```go
sb, _ := client.Sandboxes().Get(ctx, "default", "my-sandbox")

result, err := client.Sandboxes().DetachProvider(ctx,
    "default", "my-sandbox",
    "openai",
    sb.ResourceVersion,
)
fmt.Println(result.Detached) // true if actually detached
```

## ListProviders

Lists all providers currently attached to a sandbox.

```go
providers, err := client.Sandboxes().ListProviders(ctx, "default", "my-sandbox")
for _, p := range providers {
    fmt.Printf("provider: %s (type: %s)\n", p.Name, p.Type)
}
```

## WaitReady

Blocks until the sandbox reaches the `Ready` phase, returning the final sandbox state. Under the hood, WaitReady polls via `Get` at a configurable interval (default 500ms). Use context cancellation or deadlines to set a timeout.

If the sandbox enters the `Error` phase, WaitReady returns immediately with a `StatusError`.

```go
// Wait with a 30-second timeout
ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()

sb, err := client.Sandboxes().WaitReady(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
fmt.Println(sb.Status.Phase) // "Ready"

// Custom poll interval
sb, err := client.Sandboxes().WaitReady(ctx, "default", "my-sandbox", v1.WaitOptions{
    PollInterval: 2 * time.Second,
})
```

There is no dedicated WaitReady RPC. The SDK implements this by polling `GetSandbox` until the sandbox phase is `Ready` or `Error`.

## Watch

Opens a server-streaming connection to observe sandbox state changes in real time. Returns a `WatchInterface[*Sandbox]` that delivers events through a channel.

The `WatchInterface[T]` provides:

- `ResultChan() <-chan Event[T]` returns the channel of events
- `Stop()` closes the stream and the channel

Each `Event[T]` carries:

- `Type`: one of `EventAdded`, `EventModified`, `EventDeleted`, or `EventError`
- `Object`: the `*Sandbox` at that point in time (`nil` for `EventError`)

```go
watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
defer watcher.Stop()

for event := range watcher.ResultChan() {
    switch event.Type {
    case v1.EventModified:
        fmt.Printf("phase: %s\n", event.Object.Status.Phase)
    case v1.EventDeleted:
        fmt.Println("sandbox deleted")
        return
    case v1.EventError:
        fmt.Println("watch error")
        return
    }
}
```

Setting `StopOnTerminal: true` causes the watcher to close automatically once the sandbox reaches a terminal phase (`Ready` or `Error`). This is useful for provisioning flows where you only care about the outcome.

```go
watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox", v1.WatchOptions{
    StopOnTerminal: true,
})
if err != nil {
    log.Fatal(err)
}

for event := range watcher.ResultChan() {
    fmt.Printf("phase: %s\n", event.Object.Status.Phase)
}
// Channel closes after Ready or Error
```

## GetLogs

Retrieves log entries from a sandbox. The sandbox is looked up by name (the SDK resolves the name to an internal ID automatically). Use functional options to filter results.

**Available options:**

| Option | Description |
|--------|-------------|
| `WithLogLines(n uint32)` | Maximum number of log lines to return |
| `WithLogSince(t time.Time)` | Only include entries at or after this time |
| `WithLogSources(sources ...string)` | Filter by source (e.g., `"gateway"`, `"sandbox"`) |
| `WithLogMinLevel(level string)` | Minimum log level (e.g., `"WARN"`, `"ERROR"`) |

```go
// Get the last 50 log lines
result, err := client.Sandboxes().GetLogs(ctx, "default", "my-sandbox",
    v1.WithLogLines(50),
)
for _, line := range result.Lines {
    fmt.Printf("[%s] %s: %s\n", line.Level, line.Source, line.Message)
}

// Filter by source and level since a specific time
result, err := client.Sandboxes().GetLogs(ctx, "default", "my-sandbox",
    v1.WithLogSources("gateway"),
    v1.WithLogMinLevel("WARN"),
    v1.WithLogSince(time.Now().Add(-1*time.Hour)),
)
```

The `LogResult` contains:

- `Lines []LogLine`: log entries in chronological order
- `BufferTotal uint32`: total number of lines available in the server's buffer

Each `LogLine` has `Timestamp`, `Level`, `Target`, `Message`, `Source`, and `Fields` (structured key-value data).

See also: [Error Handling](../error-handling.md), [Testing](../testing.md)
