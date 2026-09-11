# Services

Accessor: `client.Services()`

Expose, inspect, and manage network services attached to sandboxes. Services provide
external access to ports running inside a sandbox via managed endpoints.

## Expose

Expose a port from a sandbox as a named service endpoint. Set `domain` to `true`
to assign a DNS-routable domain name to the service.

```go
endpoint, err := client.Services().Expose(ctx, "default", "my-sandbox", "web", 8080, true)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Service available at: %s\n", endpoint.URL)
```

## List

`List` returns a lazy pager over exposed services. Use `ListAll` to collect
every page.

```go
services, err := client.Services().ListAll(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
for _, svc := range services {
    fmt.Printf("  %s -> port %d (%s)\n", svc.ServiceName, svc.TargetPort, svc.URL)
}

// Platform Admin only: list services across all workspaces
allServices, err := client.Services().ListAll(ctx, "", "", v1.ListOptions{
    AllWorkspaces: true,
})
```

## Delete

Remove an exposed service. The underlying sandbox port remains accessible
internally but is no longer reachable through the service endpoint.

```go
err := client.Services().Delete(ctx, "default", "my-sandbox", "web")
if err != nil {
    log.Fatal(err)
}
```

See also: [Error Handling](../error-handling.md), [Testing](../testing.md)
