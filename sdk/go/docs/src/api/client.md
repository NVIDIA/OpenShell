# Client

Constructor: `v1.NewClient(config)`

The `ClientInterface` is the root entry point for all SDK operations. It provides
typed accessors for each resource domain and manages the underlying gRPC connection.

## Methods

| Accessor | Returns | Description |
|----------|---------|-------------|
| `Sandboxes()` | `SandboxInterface` | Sandbox lifecycle management |
| `Providers()` | `ProviderInterface` | Provider CRUD and idempotent ensure |
| `Services()` | `ServiceInterface` | Service exposure and management |
| `Exec()` | `ExecInterface` | Command execution (run, stream, interactive) |
| `Files()` | `FileInterface` | File upload and download |
| `Health()` | `HealthInterface` | Gateway health checking |
| `SSH()` | `SSHInterface` | SSH session and tunnel management |
| `TCP()` | `TCPInterface` | TCP port forwarding |
| `Config()` | `ConfigInterface` | Sandbox and gateway configuration |
| `Policy()` | `PolicyInterface` | Draft policy review workflow |
| `Close()` | `error` | Close the gRPC connection |

Sub-client hierarchy: `Providers()` has two nested accessors:
- `client.Providers().Profiles()` returns `ProfileInterface`
- `client.Providers().Refresh()` returns `RefreshInterface`

## Creating a Client

```go
import v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken("my-token"),
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## Configuration

The `Config` struct controls connection behavior:

```go
type Config struct {
    Address     string         // Gateway address (host:port)
    TLS         *TLSConfig     // TLS settings (nil uses system defaults)
    Auth        AuthProvider   // Authentication provider
    Timeout     time.Duration  // Default timeout for all operations (0 = no timeout)
    RetryPolicy *RetryPolicy   // Retry configuration (nil = no automatic retries)
    Logger      Logger         // Custom logger (nil = no logging)
}
```

Authentication providers:
- `v1.StaticToken(token)` provides a fixed bearer token
- `v1.NoAuth()` skips authentication (for local development)

## Testing

For unit tests, use the fake client instead of a real connection:

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"

client := fake.NewClient()
defer client.Close()
```

The fake client implements the full `ClientInterface` with in-memory stores.
See [Testing](../testing.md) for details.

See also: [Getting Started](../getting-started.md), [Architecture](../architecture.md)
