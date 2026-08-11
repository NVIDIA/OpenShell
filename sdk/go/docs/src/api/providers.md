# Providers

Accessor: `client.Providers()`

Register and manage compute providers (AI inference endpoints). Exposes
sub-clients for [Profiles](profiles.md) and [Refresh](refresh.md).

## Create

Register a new provider with the gateway.

```go
provider, err := client.Providers().Create(ctx, "default", &v1.Provider{
    Name: "my-openai",
    Type: "openai",
    Spec: v1.ProviderSpec{
        Credentials: map[string]string{
            "api_key": "sk-...",
        },
        Config: map[string]string{
            "base_url": "https://api.openai.com/v1",
        },
    },
})
if err != nil {
    log.Fatal(err)
}
fmt.Println("Created provider:", provider.Name)
```

## Get

Fetch a provider by name.

```go
provider, err := client.Providers().Get(ctx, "default", "my-openai")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Provider type:", provider.Type)
```

## List

List all registered providers, with optional pagination.

```go
// List all providers
providers, err := client.Providers().List(ctx, "default")
if err != nil {
    log.Fatal(err)
}
for _, p := range providers {
    fmt.Println(p.Name, p.Type)
}

// With pagination
providers, err = client.Providers().List(ctx, "default", v1.ListOptions{
    Limit:  10,
    Offset: 0,
})
```

## Update

Update an existing provider's configuration or credentials.

```go
provider, err := client.Providers().Get(ctx, "default", "my-openai")
if err != nil {
    log.Fatal(err)
}

provider.Spec.Credentials["api_key"] = "sk-new-key"
updated, err := client.Providers().Update(ctx, "default", provider)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Updated provider:", updated.Name)
```

## Delete

Remove a provider by name.

```go
err := client.Providers().Delete(ctx, "default", "my-openai")
if err != nil {
    log.Fatal(err)
}
```

## Ensure

Create or update a provider in a single idempotent call. If a provider with the given name exists, it is updated; otherwise a new one is created. This is the recommended way to register providers because it avoids "already exists" errors when re-registering.

```go
provider, err := client.Providers().Ensure(ctx, "default", &v1.Provider{
    Name: "my-openai",
    Type: "openai",
    Spec: v1.ProviderSpec{
        Credentials: map[string]string{
            "api_key": "sk-...",
        },
    },
})
if err != nil {
    log.Fatal(err)
}
fmt.Println("Provider ready:", provider.Name)
```

Ensure is an SDK-level convenience. It calls `GetProvider` first, then either `CreateProvider` or `UpdateProvider` depending on whether the provider already exists.

## Sub-Clients

The `ProviderInterface` exposes two sub-client accessors for related operations. These are pure client-side accessors with no corresponding gRPC call.

### Profiles

`client.Providers().Profiles()` returns a [ProfileInterface](profiles.md) for managing provider type profiles. Profiles define templates and defaults for different provider types.

### Refresh

`client.Providers().Refresh()` returns a [RefreshInterface](refresh.md) for configuring credential refresh strategies. Use it to set up automatic credential rotation for providers with expiring credentials.

## Provider

The `Provider` type represents a registered compute provider.

| Field             | Type                   | Description                                |
|-------------------|------------------------|--------------------------------------------|
| `ID`              | string                 | Server-assigned unique identifier          |
| `Name`            | string                 | User-chosen name (unique per gateway)      |
| `Type`            | string                 | Provider type (e.g., `"openai"`, `"azure"`) |
| `CreatedAt`       | time.Time              | Timestamp of creation                      |
| `Labels`          | map[string]string      | Key-value metadata labels                  |
| `ResourceVersion` | uint64                 | Optimistic concurrency version             |
| `Spec`            | ProviderSpec           | Configuration and credentials              |

## ProviderSpec

`ProviderSpec` holds provider-specific configuration and credentials.

| Field                  | Type                      | Description                                     |
|------------------------|---------------------------|-------------------------------------------------|
| `Credentials`          | map[string]string         | Authentication credentials (e.g., API keys)     |
| `Config`               | map[string]string         | Provider-specific configuration values          |
| `CredentialExpiresAt`  | map[string]time.Time      | Expiration timestamps for credentials           |

See also: [Profiles](profiles.md), [Refresh](refresh.md), [Error Handling](../error-handling.md), [Testing](../testing.md)
