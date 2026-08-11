# Files

Accessor: `client.Files()`

`FileInterface` reserves the upload and download API while keeping sandbox lookup
and SSH-session lifecycle behavior stable. The standalone SDK does not currently
ship an SSH file-transfer transport, so both operations return
`v1.ErrTransportNotAvailable` before performing local validation or gateway RPCs.

## Upload

Detect transport availability programmatically:

```go
err := client.Files().Upload(ctx, "default", "sandbox-123", "./data/config.yaml", "/app/config.yaml")
if errors.Is(err, v1.ErrTransportNotAvailable) {
    // Use another transfer mechanism until an SSH transport is available.
} else if err != nil {
    log.Fatal(err)
}
```

## Download

`Download` has the same capability gate:

```go
err := client.Files().Download(ctx, "default", "sandbox-123", "/app/output.log", "./output.log")
if errors.Is(err, v1.ErrTransportNotAvailable) {
    // Use another transfer mechanism until an SSH transport is available.
} else if err != nil {
    log.Fatal(err)
}
```

See also: [Error Handling](../error-handling.md), [Testing](../testing.md)
