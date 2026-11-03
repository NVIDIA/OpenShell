# Health

Accessor: `client.Health()`

Check the health status of the connected OpenShell gateway.

## Inspect workload compatibility

Use `GetGatewayInfo` to inspect the configured driver's workload platform and
reported fixed execution restrictions:

```go
info, err := client.Health().GetGatewayInfo(ctx)
if err != nil {
    log.Fatal(err)
}
for _, driver := range info.ComputeDrivers {
    if workload := driver.WorkloadCompatibility; workload != nil {
        fmt.Printf("%s: %+v\n", driver.Name, *workload)
    } else {
        fmt.Printf("%s: workload compatibility unreported\n", driver.Name)
    }
}
```

The workload can use a different operating system from the gateway host.
Empty platform fields and an empty restriction list remain unreported. They
do not establish unrestricted execution or guarantee that a command will run.
This inspection is separate from the gateway health check below.

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
