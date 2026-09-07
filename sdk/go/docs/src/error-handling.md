# Error Handling

Gateway status failures and SDK validation failures use `*v1.StatusError`, which carries a machine-readable `Code` and a human-readable `Message`. Local I/O, transport setup, and sentinel errors may use other Go error types. The SDK provides predicate functions for classified status errors.

## StatusError

When an operation returns a classified status error, inspect it directly or use the convenience predicates below. Use `errors.Is` for documented sentinel errors such as `ErrTransportNotAvailable`.

```go
var se *v1.StatusError
if errors.As(err, &se) {
    fmt.Printf("code: %s, message: %s\n", se.Code, se.Message)
    // se.Details contains optional structured metadata
}
```

| Field     | Type              | Description                          |
|-----------|-------------------|--------------------------------------|
| `Code`    | `ErrorCode`       | Machine-readable error classification |
| `Message` | `string`          | Human-readable error description      |
| `Details` | `map[string]string` | Optional structured metadata        |

## Predicate Functions

Use these top-level functions to check error types. They work with wrapped errors via `errors.As`.

| Function             | ErrorCode            | When it fires                                  |
|----------------------|----------------------|-------------------------------------------------|
| `v1.IsNotFound`      | `ErrorNotFound`      | Resource does not exist (sandbox, provider, etc.) |
| `v1.IsAlreadyExists` | `ErrorAlreadyExists` | Resource with that name already exists           |
| `v1.IsConflict`      | `ErrorConflict`      | Optimistic concurrency violation or invalid state transition |
| `v1.IsUnavailable`   | `ErrorUnavailable`   | Gateway is unreachable or client is closed       |
| `v1.IsUnimplemented` | `ErrorUnimplemented` | Operation not supported by the gateway version   |
| `v1.IsPermissionDenied` | `ErrorPermissionDenied` | Insufficient permissions                  |
| `v1.IsInvalidArgument` | `ErrorInvalidArgument` | Invalid request parameters                  |
| `v1.IsDeadlineExceeded` | `ErrorDeadlineExceeded` | Operation timed out                       |
| `v1.IsCancelled`     | `ErrorCancelled`     | Operation was cancelled (context cancellation)   |

For `ErrorInternal` (server-side errors), no convenience predicate exists. Match it directly via the `Code` field:

```go
var se *v1.StatusError
if errors.As(err, &se) && se.Code == v1.ErrorInternal {
    fmt.Println("Internal server error:", se.Message)
}
```

## Common Patterns

### Not Found

Handle missing resources gracefully:

```go
sb, err := client.Sandboxes().Get(ctx, "default", "my-sandbox")
if v1.IsNotFound(err) {
    fmt.Println("Sandbox does not exist, creating...")
    sb, err = client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
}
if err != nil {
    log.Fatal(err)
}
```

### Already Exists

Guard against duplicate creation:

```go
_, err := client.Providers().Create(ctx, "default", &v1.Provider{
    Name: "openai",
    Type: "openai",
})
if v1.IsAlreadyExists(err) {
    fmt.Println("Provider already registered, skipping")
} else if err != nil {
    log.Fatal(err)
}
```

Alternatively, use `Ensure` for idempotent registration:

```go
// Create-or-update in a single call
provider, err := client.Providers().Ensure(ctx, "default", &v1.Provider{
    Name: "openai",
    Type: "openai",
})
```

### Conflict (Optimistic Concurrency)

When two clients modify the same resource concurrently, the second write receives a conflict error. Retry by re-reading the resource:

```go
sb, _ := client.Sandboxes().Get(ctx, "default", "my-sandbox")

result, err := client.Sandboxes().AttachProvider(ctx,
    "default", "my-sandbox", "openai", sb.ResourceVersion,
)
if v1.IsConflict(err) {
    // Another client modified the sandbox — re-read and retry
    sb, _ = client.Sandboxes().Get(ctx, "default", "my-sandbox")
    result, err = client.Sandboxes().AttachProvider(ctx,
        "default", "my-sandbox", "openai", sb.ResourceVersion,
    )
}
if err != nil {
    log.Fatal(err)
}
```

### Unavailable

Handle gateway connectivity issues:

```go
sb, err := client.Sandboxes().Get(ctx, "default", "my-sandbox")
if v1.IsUnavailable(err) {
    fmt.Println("Gateway is not reachable, check connection")
    // Implement retry with backoff
}
```

### Unimplemented

Detect unsupported operations gracefully:

```go
_, err := client.Sandboxes().GetLogs(ctx, "default", "my-sandbox")
if v1.IsUnimplemented(err) {
    fmt.Println("Log retrieval not supported by this gateway version")
}
```

## Retry with Backoff

For transient errors like `Unavailable` or `DeadlineExceeded`, use exponential backoff only when the operation is idempotent or carries an idempotency/concurrency token. A timeout does not prove that a mutating request was not applied.

```go
func withRetry(ctx context.Context, maxAttempts int, fn func() error) error {
    backoff := 100 * time.Millisecond

    for attempt := 0; attempt < maxAttempts; attempt++ {
        err := fn()
        if err == nil {
            return nil
        }

        // Only retry transient errors
        if !v1.IsUnavailable(err) && !v1.IsDeadlineExceeded(err) {
            return err
        }

        // Add jitter to prevent thundering herd after outages
        jitter := time.Duration(rand.Int63n(int64(backoff) / 2))

        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(backoff + jitter):
            backoff *= 2
        }
    }
    return fmt.Errorf("exhausted %d retry attempts", maxAttempts)
}
```

Usage:

```go
var sb *v1.Sandbox
err := withRetry(ctx, 3, func() error {
    var e error
    sb, e = client.Sandboxes().Get(ctx, "default", "my-sandbox")
    return e
})
```

## Context Cancellation

All SDK methods accept a `context.Context`. Use context deadlines and cancellation to control timeouts:

```go
// 5-second timeout for a single call
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

sb, err := client.Sandboxes().Get(ctx, "default", "my-sandbox")
if v1.IsDeadlineExceeded(err) {
    fmt.Println("Request timed out")
}
```

See also: [Testing](testing.md) for how the fake client returns the same error codes.
