# Config

Accessor: `client.Config()`

Retrieve and update configuration for sandboxes and the gateway.

## GetSandbox

Retrieve the current configuration for a specific sandbox.

```go
config, err := client.Config().GetSandbox(ctx, "default", "sandbox-123")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Sandbox config: policy_version=%d, revision=%d\n",
    config.PolicyVersion, config.ConfigRevision)
```

## GetGateway

Retrieve the gateway-level configuration.

```go
config, err := client.Config().GetGateway(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Gateway settings revision: %d\n", config.SettingsRevision)
```

## Update

Apply a configuration update. The update is validated before being applied.

```go
result, err := client.Config().Update(ctx, "default", &v1.ConfigUpdate{
    Name:       "sandbox-123",
    SettingKey:  "idle_timeout",
    SettingValue: &v1.SettingValue{
        Type:      v1.SettingValueString,
        StringVal: "30m",
    },
})
if err != nil {
    // See [Error Handling](../error-handling.md) for validation errors
    log.Fatal(err)
}
fmt.Printf("Config updated: revision=%d\n", result.SettingsRevision)
```

See also: [Error Handling](../error-handling.md)
