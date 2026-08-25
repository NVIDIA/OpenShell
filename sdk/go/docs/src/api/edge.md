# Edge

Package: `openshell/v1/edge`

The edge package provides utilities for connecting to OpenShell gateways
through edge proxies such as Cloudflare Access. It includes auth wrappers
for edge proxy headers and a WebSocket tunnel proxy for gRPC transport
through HTTP/1.1-only proxies.

## Cloudflare Access

Wrap any `AuthProvider` with Cloudflare Access headers
(`cf-access-jwt-assertion` and `CF_Authorization` cookie):

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/edge"

base := v1.StaticToken("my-gateway-token")
auth, err := edge.CloudflareAccess(base, os.Getenv("CF_ACCESS_TOKEN"))
if err != nil {
    log.Fatal(err)
}
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    auth,
})
```

CloudflareAccess composes with any auth provider, including `RefreshableToken`
for automatic token refresh:

```go
tokenSource := oauth2Config.TokenSource(ctx, initialToken)
refreshAuth, err := v1.RefreshableToken(tokenSource)
if err != nil {
    log.Fatal(err)
}
auth, err := edge.CloudflareAccess(refreshAuth, cfToken)
```

## WebSocket Tunnel

`TunnelProxy` bridges gRPC connections over a WebSocket tunnel for edge
proxies that reject standard HTTP/2 POST requests. The tunnel carries
its own edge token for proxy authentication, independent of the
application-level auth provider.

```go
tunnel, err := edge.NewTunnelProxy(
    "wss://gateway.example.com/ws",
    os.Getenv("CF_ACCESS_TOKEN"),
)
if err != nil {
    log.Fatal(err)
}
defer tunnel.Close()

auth := v1.StaticToken("my-gateway-token")
client, err := v1.NewClient(v1.Config{
    Address: tunnel.Addr(),
    Auth:    auth,
    TLS:     &v1.TLSConfig{Insecure: true}, // local tunnel
})
```

## Functions

| Function | Description |
|----------|-------------|
| `CloudflareAccess(base, edgeToken)` | Wrap an AuthProvider with Cloudflare Access headers |
| `NewTunnelProxy(url, edgeToken, opts...)` | Create a WebSocket tunnel proxy for gRPC-over-HTTP/1.1 |

## TunnelProxy Methods

| Method | Description |
|--------|-------------|
| `Addr()` | Local listener address for gRPC client to dial |
| `Close()` | Gracefully drain in-flight connections and shut down |

## TunnelOption

| Constructor | Effect |
|-------------|--------|
| `WithTunnelTLS(cfg)` | Configure TLS for the WebSocket connection |
| `WithTunnelLogger(l)` | Set a logger for tunnel events |
| `WithCloseTimeout(d)` | Override the graceful shutdown timeout (default 5s) |

## Thread Safety

All exported functions and methods are safe for concurrent use.
`Close` is idempotent and safe to call multiple times.
