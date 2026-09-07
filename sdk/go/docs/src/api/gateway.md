# Gateway

Package: `openshell/v1/gateway`

The gateway package reads on-disk gateway configurations created by the
OpenShell Rust CLI and constructs fully wired SDK clients. It eliminates
the boilerplate of locating config files, parsing metadata, loading
tokens, and wiring auth providers.

## Quick Start

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"

// Connect to a named gateway
client, err := gateway.NewClient("prod")
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## Functions

| Function | Description |
|----------|-------------|
| `NewClient(name, opts...)` | Create a fully wired SDK client from gateway config |
| `LoadConfig(name)` | Parse gateway config without connecting |
| `ListGateways()` | Enumerate all available gateways |

### NewClient

```go
func NewClient(name string, opts ...ClientOption) (*v1.Client, error)
```

Creates a fully configured SDK client for the named gateway. If `name`
is empty, the active gateway (set via `openshell gateway use`) is used.

The function resolves the gateway directory, parses `metadata.json`,
loads tokens lazily, maps the auth mode to an SDK auth provider, and
applies any `ClientOption` values before delegating to `v1.NewClient`.

```go
// Named gateway
client, err := gateway.NewClient("prod")

// Active gateway
client, err := gateway.NewClient("")

// With options
client, err := gateway.NewClient("staging",
    gateway.WithTimeout(10 * time.Second),
    gateway.WithLogger(myLogger),
)
```

**Errors**: `ErrGatewayNotFound`, `ErrConfigParse`, `ErrTokenLoad`,
`ErrUnsupportedAuthMode`, `ErrInvalidGatewayName`, `ErrNoActiveGateway`

### LoadConfig

```go
func LoadConfig(name string) (*Config, error)
```

Parses gateway configuration without creating a client connection.
Returns a frozen snapshot; changes to on-disk files after the call
are not reflected.

```go
cfg, err := gateway.LoadConfig("staging")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Endpoint: %s, Auth: %s\n", cfg.Endpoint, cfg.AuthMode)
```

### ListGateways

```go
func ListGateways() ([]Info, error)
```

Enumerates all available gateways from user and system directories.
User gateways appear first. Duplicate names resolve to user precedence.
Returns an empty slice (not an error) when no gateways are configured.

```go
gateways, err := gateway.ListGateways()
for _, gw := range gateways {
    fmt.Printf("%s (active=%v, source=%s)\n", gw.Name, gw.Active, gw.Source)
}
```

## Types

### Config

```go
type Config struct {
    Name     string       // Validated gateway name
    Endpoint string       // Host:port of the gateway
    AuthMode AuthMode     // Resolved auth mode
    Source   ConfigSource // User or System origin
    Dir      string       // Absolute path to gateway config directory
}
```

### Info

```go
type Info struct {
    Name   string       // Gateway name from directory listing
    Active bool         // Whether this is the active gateway
    Source ConfigSource // User or System origin
}
```

### AuthMode

| Value | Constant | SDK AuthProvider |
|-------|----------|-----------------|
| `""` or `"none"` | `AuthModeNone` | `v1.NoAuth()` |
| `"plaintext"` | `AuthModePlaintext` | `v1.NoAuth()` + insecure TLS |
| `"cloudflare_jwt"` | `AuthModeCloudflareJWT` | Lazy edge token auth |
| `"oidc"` | `AuthModeOIDC` | `v1.RefreshableToken` with disk source |
| `"mtls"` | `AuthModeMTLS` | Unsupported (use `WithAuth`) |

### ClientOption

| Constructor | Effect |
|-------------|--------|
| `WithLogger(l)` | Set logger on the SDK client |
| `WithTimeout(d)` | Set connection timeout |
| `WithTLS(cfg)` | Override TLS settings from gateway config |
| `WithAuth(provider)` | Override auto-resolved auth provider |
| `WithRetryPolicy(p)` | Set retry policy |

## Error Handling

All errors support `errors.Is` for classification:

```go
client, err := gateway.NewClient("my-gateway")
if errors.Is(err, gateway.ErrGatewayNotFound) {
    fmt.Println("Gateway not configured. Run: openshell gateway add my-gateway")
}
if errors.Is(err, gateway.ErrTokenLoad) {
    fmt.Println("Token expired or missing. Run: openshell gateway login my-gateway")
}
```

| Error | Meaning |
|-------|---------|
| `ErrGatewayNotFound` | No gateway directory in user or system paths |
| `ErrConfigParse` | metadata.json missing or malformed |
| `ErrTokenLoad` | Token file missing or unreadable |
| `ErrUnsupportedAuthMode` | Unrecognized auth_mode value |
| `ErrInvalidGatewayName` | Name fails validation |
| `ErrNoActiveGateway` | No active gateway configured |

## On-Disk Layout

The package reads gateway metadata from these locations:

```
$XDG_CONFIG_HOME/openshell/          (user, default: ~/.config/openshell/)
├── active_gateway                   # Plain text: active gateway name
└── gateways/
    └── <name>/
        ├── metadata.json            # {"endpoint":"...","auth_mode":"...","name":"..."}
        ├── edge_token               # Cloudflare edge JWT (plaintext)
        ├── cf_token                 # Legacy edge token (fallback)
        └── oidc_token.json          # OIDC token bundle

/etc/openshell/gateways/             (system, fallback)
```

User gateways take precedence over system gateways with the same name.

## Thread Safety

All exported functions (`NewClient`, `LoadConfig`, `ListGateways`) are
safe for concurrent use from multiple goroutines. Token loading uses
internal synchronization.
