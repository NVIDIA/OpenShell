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
}, v1.CreateOptions{ServiceExposures: []v1.ServiceExposure{
    {TargetPort: 8080},
}})
fmt.Println(sb.ServiceURLs[""])
```

Create-time service exposures register loopback HTTP endpoints with the
sandbox. Leave `Service` empty for the unnamed endpoint or set it to create a
named endpoint. Routing begins when the sandbox is ready.
`ServiceURLs` returns the routed URLs keyed by service name; the empty key is
the unnamed endpoint.

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

### Tool server connections

`sb.Status.EndpointStatuses` shows each configured tool server endpoint and its last accepted network result in one record. A sandbox can be `Ready` while a tool server connection fails; endpoint results do not change lifecycle readiness. OpenShell currently observes endpoints configured for MCP over HTTP.

```go
for _, endpoint := range sb.Status.EndpointStatuses {
    fmt.Printf("%s:%v%s: %s, reported %s\n",
        endpoint.Host, endpoint.Ports, endpoint.Path,
        endpoint.LastResult, endpoint.LastReportedAt)
}
```

`LastResult` is a typed `v1.EndpointResult`. For example, `v1.EndpointTransportFailed` means the transport failed before an HTTP response arrived. `v1.EndpointHTTPResponseReceived` means the server returned an HTTP status below 400; its body can still contain a tool error. Neither result establishes current availability.

OpenShell observes real traffic passively and does not expire idle observations. Keep `LastReportedAt` visible when displaying a result: it records when the gateway accepted the observation, not when the request happened. Retained evidence can be accepted after a reset. `v1.EndpointNoObservedExchange` has an empty timestamp and retains the configured address, so the endpoint remains identifiable before traffic is observed or after evidence is invalidated.

## List

`List` constructs a lazy pager; `NextPage` fetches one page at a time.
`PageSize` controls each request, and `ListAll` explicitly exhausts the pager.

```go
// List all sandboxes
sandboxes, err := client.Sandboxes().ListAll(ctx, "default")

// Process one page at a time
pages, err := client.Sandboxes().List("default", v1.ListOptions{PageSize: 10})
page, err := pages.NextPage(ctx)

// With a page size and label filtering
sandboxes, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{
    PageSize:      10,
    LabelSelector: "team=platform",
})

// Platform Admin only: list across all workspaces
allSandboxes, err := client.Sandboxes().ListAll(ctx, "", v1.ListOptions{
    AllWorkspaces: true,
})
```

## Delete

Deletes a sandbox by name.

```go
deletion, err := client.Sandboxes().Delete(ctx, "default", "my-sandbox", v1.DeleteOptions{AllowMissing: true})
```

Missing targets return `NotFound` unless `AllowMissing` is true. Inspect
`deletion.Outcome`: `DeletionAccepted` means cleanup is pending, while
`DeletionCompleted` and `DeletionAlreadyAbsent` establish logical completion.
Unknown values do not establish completion. `deletion.SandboxID` identifies the
original sandbox; do not confuse a same-name replacement with that target.
Allowing absence does not make a retry safe if names can be reused.

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

## WatchLogs

Streams a sandbox's log lines and platform events with loss-aware resume. Returns a `WatchInterface[*WatchLogEvent]`.

Each delivered item carries an opaque `Cursor`. The watcher tracks the highest cursor it has seen, reconnects transparently when the stream drops, and asks the gateway to replay only what follows that cursor, so a reconnect neither loses nor duplicates events.

Every `Event[*WatchLogEvent]` has `Type` `EventAdded`, except a terminal failure, which arrives as `EventError` with `Err` set and no `Object`. The `Object.Kind` field selects the populated payload:

| Kind | Payload | Meaning |
|------|---------|---------|
| `WatchLogKindLog` | `Log *LogLine` | A log line |
| `WatchLogKindEvent` | `Event *PlatformEvent` | A runtime event from the compute backend |
| `WatchLogKindWarning` | `Warning string` | Recoverable loss — the server skipped ahead after a lag and the stream continues |

**Available options** (`WatchLogsOptions`):

| Field | Description |
|-------|-------------|
| `FollowLogs bool` | Stream log lines. Defaults to true when neither follow flag is set |
| `FollowEvents bool` | Stream platform events |
| `LogSources []string` | Filter log lines by source (e.g. `"gateway"`, `"sandbox"`) |
| `LogMinLevel string` | Minimum log level (e.g. `"WARN"`) |
| `ResumeAfterCursor string` | Replay only what follows a cursor from an earlier watch |
| `LogTailLines uint32` | Bound the initial log backfill. Ignored when resuming from a cursor |
| `EventTail uint32` | Bound the initial event backfill. Ignored when resuming from a cursor |

```go
watcher, err := client.Sandboxes().WatchLogs(ctx, "default", "my-sandbox", v1.WatchLogsOptions{
    FollowLogs:   true,
    FollowEvents: true,
    LogTailLines: 100,
})
if err != nil {
    log.Fatal(err)
}
defer watcher.Stop()

var cursor string
for event := range watcher.ResultChan() {
    if event.Type == v1.EventError {
        if v1.IsOutOfRange(event.Err) {
            // Unrecoverable gap: events after the resume point are gone.
            fmt.Println("log history was trimmed; some events were lost")
        }
        break
    }
    switch item := event.Object; item.Kind {
    case v1.WatchLogKindLog:
        fmt.Printf("[%s] %s\n", item.Log.Level, item.Log.Message)
    case v1.WatchLogKindEvent:
        fmt.Printf("event %s: %s\n", item.Event.Reason, item.Event.Message)
    case v1.WatchLogKindWarning:
        fmt.Printf("warning: %s\n", item.Warning)
    }
    if item := event.Object; item.Cursor > cursor {
        cursor = item.Cursor
    }
}
```

Loss is never silent. A recoverable gap arrives as a `WatchLogKindWarning` item and the stream continues. An unrecoverable gap ends the stream with an `EventError` carrying `ErrorOutOfRange`: the resume point is gone, so the events after it cannot be replayed. The SDK does not retry that error, because restarting from the tail would hide the loss. To continue anyway, start a new watch with an empty `ResumeAfterCursor`; retrying the same cursor fails identically.

Persist the highest cursor to resume across process restarts:

```go
watcher, err := client.Sandboxes().WatchLogs(ctx, "default", "my-sandbox", v1.WatchLogsOptions{
    FollowLogs:        true,
    ResumeAfterCursor: savedCursor,
})
```

Cursors are opaque. Do not parse or construct one. The only supported operation is comparing two cursors observed on the same stream and keeping the greater one.

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
