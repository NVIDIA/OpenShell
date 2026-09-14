# TCP

Accessor: `client.TCP()`

Forward TCP connections to sandbox ports using bidirectional gRPC streaming.

## Forward

Open a bidirectional TCP forwarding stream to a specific port inside a sandbox.
Returns an `io.ReadWriteCloser` that proxies data between the caller and the
sandbox port over gRPC streaming.

```go
conn, err := client.TCP().Forward(ctx, "default", "sandbox-123", 8080)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Exchange protocol bytes with the service through the tunnel.
_, err = conn.Write([]byte("ping\n"))
if err != nil {
    log.Fatal(err)
}

buf := make([]byte, 4096)
n, err := conn.Read(buf)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Response: %s\n", buf[:n])
```

## Listen

Bind a local address that forwards every connection to a sandbox port. The
returned `ForwardListener` owns its accept loop and all bridge goroutines; it is
a lifecycle handle with `Addr` and `Close`, not a `net.Listener`.

```go
forward, err := client.TCP().Listen(ctx, "default", "sandbox-123", 8080, 0)
if err != nil {
    log.Fatal(err)
}
defer forward.Close()

conn, err := net.Dial("tcp", forward.Addr().String())
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
```

Do not pass `ForwardListener` to `http.Serve`. Dial its address with the client
for the protocol exposed by the sandbox service.

TCP forwarding is lower-level than [SSH tunneling](ssh.md). Use TCP forwarding
when you need direct port access without SSH session overhead.

See also: [SSH Tunneling](ssh.md), [Error Handling](../error-handling.md)
