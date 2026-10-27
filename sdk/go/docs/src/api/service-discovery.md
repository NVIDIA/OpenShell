# Service discovery

Accessor: `client.ServiceRoutes()` on the concrete SDK client. Consumers can
accept the narrow `ServiceDiscoveryInterface`; existing `ClientInterface` mocks
are unchanged. Discovery reads accepted supervisor installations for an explicit
workspace selection and enforces the gateway's authorization for that selection.

```go
snapshot, err := client.ServiceRoutes().Snapshot(ctx, "default")
if err != nil {
    return err
}
for _, route := range snapshot.Routes {
    fmt.Println(route.Hostname, route.Endpoint, route.ExpiresAt)
}

watch, err := client.ServiceRoutes().Watch(ctx, "default")
if err != nil {
    return err
}
defer watch.Close()
for {
    replacement, err := watch.Recv()
    if errors.Is(err, io.EOF) {
        break // reconnect and relist after normal bounded stream completion
    }
    if err != nil {
        return err // an error is not an empty replacement
    }
    _ = replacement // atomically replace the complete cached workspace view
}
```

The SDK returns complete replacement snapshots without background prefetch or
implicit reconnect. A caller must expire cached entries at `ExpiresAt` even when
discovery is unavailable, reconnect/relist after stream termination, and clear
routes when authorization is revoked. `Close` cancels the RPC and is safe to call
concurrently with one receiving goroutine. Derive a cancelable watch context and
choose snapshot deadlines appropriate for the consumer.

Preserve `Hostname` as TLS SNI and HTTP authority when dialing `Endpoint`.
`InstallationVersion` stays stable across lease-only renewal; `Revision` changes
with expiry and is only an equality token. Installation is neither application
health nor proof of external ingress acceptance. Discovery-only certificate
identities can receive explicit selected-workspace or platform grants.

## Workspace selection

Existing `Snapshot(ctx, workspace)` and `Watch(ctx, workspace)` methods retain
single-workspace behavior. Use `SnapshotFor` and `WatchFor` for a named set or all
active workspaces:

```go
scope := openshell.ServiceRouteScope{Workspaces: []string{"team-a", "team-b"}}
snapshot, err := client.ServiceRoutes().SnapshotFor(ctx, scope)
watch, err := client.ServiceRoutes().WatchFor(ctx, openshell.ServiceRouteScope{AllWorkspaces: true})
```

Select either a nonempty set of up to 64 distinct workspace names or all
workspaces. Selection does not grant access: every workspace must be authorized.
All-workspaces queries require explicit platform authority or a discovery-only
certificate grant. Watches deliver complete replacements and recheck grants;
clients must independently expire routes and reconnect after bounded completion.
