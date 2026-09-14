# Quick Start

This guide walks you through installing the OpenShell Go SDK, connecting to a gateway, creating a sandbox, running a command, and cleaning up. You should be up and running in under 5 minutes.

## Prerequisites

- Go 1.25 or later
- Access to an OpenShell gateway (address and authentication token)

## Installation

Add the SDK to your Go module:

```bash
go get github.com/NVIDIA/OpenShell/sdk/go@latest
```

## Connect to the Gateway

Create a client by providing the gateway address and authentication credentials:

```go
package main

import (
    "context"
    "fmt"
    "log"

    v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

func main() {
    client, err := v1.NewClient(v1.Config{
        Address: "gateway.example.com:443",
        Auth:    v1.StaticToken("my-token"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
```

For production use, load the token from an environment variable instead of hardcoding it:
`v1.StaticToken(os.Getenv("OPENSHELL_TOKEN"))`

The `Config` struct accepts optional fields for TLS configuration and retry policies. For development against a local gateway without TLS, use `v1.NoAuth()` and set TLS to skip verification.

## Check Gateway Health

Verify the gateway is reachable:

```go
    ctx := context.Background()

    health, err := client.Health().Check(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Gateway healthy: %v\n", health.Healthy)
```

## Create a Sandbox

Create a sandbox with a Python image:

```go
    sandbox, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{
        Template: &v1.SandboxTemplate{Image: "python:3.12"},
        Environment: map[string]string{"LANG": "en_US.UTF-8"},
    }, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created sandbox: %s\n", sandbox.Name)
```

## Wait for the Sandbox to be Ready

Sandboxes take a moment to provision. Use `WaitReady` to block until the sandbox is ready to accept commands:

```go
    sandbox, err = client.Sandboxes().WaitReady(ctx, "default", sandbox.Name)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Sandbox is ready (phase: %s)\n", sandbox.Status.Phase)
```

## Run a Command

Execute a command inside the sandbox:

```go
    result, err := client.Exec().Run(ctx, "default", sandbox.Name, []string{"echo", "hello from OpenShell"})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Output: %s", result.Stdout)
    fmt.Printf("Exit code: %d\n", result.ExitCode)
```

For long-running commands, use `Stream` to receive output incrementally, or `Interactive` for terminal-like sessions.

## Clean Up

Delete the sandbox when you are done:

```go
    err = client.Sandboxes().Delete(ctx, "default", sandbox.Name)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Sandbox deleted")
}
```

## Next Steps

- Browse the [API Overview](api/overview.md) to see all available interfaces
- Learn about [Error Handling](error-handling.md) for production code
- Set up [Testing](testing.md) with the fake client for your test suites
- Explore the [Architecture](architecture.md) to understand the SDK design
