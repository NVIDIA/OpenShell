# SSH

Accessor: `client.SSH()`

Create and manage SSH sessions for sandboxes. Supports direct SSH access and
TCP tunneling through SSH connections.

## CreateSession

Create a new SSH session for a sandbox. Returns connection details including
host, port, and authentication credentials.

```go
session, err := client.SSH().CreateSession(ctx, "default", "sandbox-123")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("SSH via %s://%s:%d\n", session.GatewayScheme, session.GatewayHost, session.GatewayPort)
```

## RevokeSession

Revoke an active SSH session, immediately terminating any connections using it.

```go
revoked, err := client.SSH().RevokeSession(ctx, session.Token)
if err != nil {
    log.Fatal(err)
}
if revoked {
    fmt.Println("Session revoked")
}
```

## Tunnel

Create an SSH tunnel that provides a bidirectional stream to a port inside a
sandbox. This combines SSH session creation with TCP forwarding into a single
operation, returning an `io.ReadWriteCloser` for the tunnel.

```go
tunnel, err := client.SSH().Tunnel(ctx, "default", "my-sandbox", 8080)
if err != nil {
    log.Fatal(err)
}
defer tunnel.Close()

// Use the tunnel as a regular io.ReadWriteCloser
_, err = tunnel.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
if err != nil {
    log.Fatal(err)
}
```

See also: [TCP Forwarding](tcp.md), [Error Handling](../error-handling.md)
