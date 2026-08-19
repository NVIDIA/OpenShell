# OIDC Login

Package: `openshell/v1/oidc`

The oidc package provides OIDC authentication for OpenShell gateways.
It supports four OAuth2 flows: browser-based authorization code with
PKCE, keyboard fallback, device code (RFC 8628), and client credentials.

## Quick Start

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/oidc"

// Gateway-aware login (reads OIDC config from gateway metadata)
token, err := oidc.Login(ctx, "my-gateway")
if err != nil {
    log.Fatal(err)
}
```

## Functions

| Function | Description |
|----------|-------------|
| `Login(ctx, gatewayName, opts...)` | Interactive login via browser or keyboard flow |
| `DeviceLogin(ctx, opts...)` | Device authorization grant (RFC 8628) |
| `ClientCredentials(ctx, opts...)` | Non-interactive client credentials grant |

### Login

```go
func Login(ctx context.Context, gatewayName string, opts ...LoginOption) (*oauth2.Token, error)
```

Performs an interactive OIDC login. When `gatewayName` is provided, the
OIDC issuer and client ID are read from the gateway's `metadata.json`.
The default flow opens a browser for authorization code exchange with
PKCE. If the provider does not support PKCE (S256), the flow proceeds
without it.

Tokens are persisted to the gateway's config directory as
`oidc_token.json`. Subsequent calls reuse a valid cached token.

For standalone use (no gateway), pass an empty `gatewayName` with
`WithIssuer` and `WithClientID`. Combine with `WithInMemory` to skip
disk persistence.

### DeviceLogin

```go
func DeviceLogin(ctx context.Context, opts ...LoginOption) (*oauth2.Token, error)
```

Performs an OAuth2 device authorization grant (RFC 8628). The flow
requests a device code and user code from the provider, displays them
via `WithDisplayFunc` (or stdout), and polls the token endpoint until
the user completes authorization.

Requires `WithIssuer` and `WithClientID`, or `WithGateway`.

### ClientCredentials

```go
func ClientCredentials(ctx context.Context, opts ...LoginOption) (*oauth2.Token, error)
```

Performs a non-interactive OAuth2 client credentials grant. Requires
`WithIssuer`, `WithClientID`, and `WithClientSecret` (or `WithGateway`
combined with `WithClientSecret`). The client secret is never included
in error messages.

## Options

| Option | Description |
|--------|-------------|
| `WithIssuer(url)` | OIDC provider issuer URL |
| `WithClientID(id)` | OAuth2 client ID |
| `WithClientSecret(secret)` | OAuth2 client secret (for client credentials) |
| `WithScopes(scopes...)` | Custom scopes (default: openid, profile, email) |
| `WithCallbackPort(port)` | Fixed port for localhost callback (default: tries 8000, then 18000) |
| `WithTimeout(d)` | Auth flow timeout (default: 2 minutes) |
| `WithKeyboardFlow()` | Use keyboard flow instead of browser |
| `WithInMemory()` | Skip token persistence to disk |
| `WithDisplayFunc(fn)` | Custom display for device code flow |
| `WithGateway(name)` | Resolve OIDC config from gateway metadata |

## Error Handling

The package defines sentinel errors for `errors.Is()` matching:

| Error | Description |
|-------|-------------|
| `ErrDiscovery` | OIDC discovery document fetch failed |
| `ErrAuthCode` | Authorization code exchange failed |
| `ErrDeviceCode` | Device code flow failed |
| `ErrClientCredentials` | Client credentials exchange failed |
| `ErrTimeout` | Authentication flow timed out |
| `ErrCallbackServer` | Localhost callback server failed |
| `ErrTokenPersist` | Token read/write failed |
| `ErrOIDCConfig` | Missing or invalid OIDC configuration |

```go
token, err := oidc.Login(ctx, "my-gateway")
if errors.Is(err, oidc.ErrDiscovery) {
    // Provider unreachable
}
if errors.Is(err, oidc.ErrTimeout) {
    // User did not complete login in time
}
```

## Gateway Integration

When a gateway's `metadata.json` contains `oidc_issuer` and
`oidc_client_id` fields, `Login` and `DeviceLogin` can resolve
configuration automatically:

```go
// Login reads OIDC config from the gateway
token, err := oidc.Login(ctx, "my-gateway")

// Then use the token with the SDK client
client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken(token.AccessToken),
})
```

## Flows

### Browser Flow (default)

1. Discovers OIDC endpoints from issuer
2. Generates PKCE code verifier and S256 challenge
3. Opens browser to authorization URL
4. Starts localhost callback server to receive the auth code
5. Exchanges code for tokens with PKCE verification
6. Persists tokens to disk

### Keyboard Flow

Same as browser flow, but prints the authorization URL for the user to
copy manually. The user pastes the authorization code back into the
terminal. Use `WithKeyboardFlow()` to enable.

### Device Code Flow (RFC 8628)

1. Requests a device code and user code from the provider
2. Displays the verification URL and user code
3. Polls the token endpoint at the provider's requested interval
4. Handles `slow_down` responses by increasing the poll interval

### Client Credentials Flow

1. Discovers OIDC endpoints from issuer
2. Exchanges client ID and secret for an access token
3. No user interaction required
