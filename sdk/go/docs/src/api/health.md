# Health

Accessor: `client.Health()`

Check the health status of the connected OpenShell gateway.

## Check

Perform a health check against the gateway. Returns the overall status and
component-level details.

```go
result, err := client.Health().Check(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Gateway healthy: %v\n", result.Healthy)
```

This is useful for readiness probes or verifying connectivity before executing
other operations.

```go
// Quick connectivity check before starting work
if result, err := client.Health().Check(ctx); err != nil {
    log.Fatalf("Gateway unreachable: %v", err)
} else if !result.Healthy {
    log.Fatal("Gateway is not healthy")
}
```

See also: [Error Handling](../error-handling.md)
