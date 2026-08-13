# API Overview

The OpenShell Go SDK exposes 12 interfaces through the sub-client pattern. You access each interface through a typed accessor on the `Client`.

## Interface Summary

### Top-Level Interfaces

| Interface | Accessor | Description |
|-----------|----------|-------------|
| [SandboxInterface](sandboxes.md) | `client.Sandboxes()` | Create, manage, and watch sandbox lifecycle |
| [ExecInterface](exec.md) | `client.Exec()` | Run commands, stream output, interactive sessions |
| [ProviderInterface](providers.md) | `client.Providers()` | Manage compute providers and their lifecycle |
| [ServiceInterface](services.md) | `client.Services()` | Expose and manage HTTP services inside sandboxes |
| [FileInterface](files.md) | `client.Files()` | Upload and download files to/from sandboxes |
| [HealthInterface](health.md) | `client.Health()` | Check gateway health status |
| [SSHInterface](ssh.md) | `client.SSH()` | Create SSH sessions and tunnels to sandboxes |
| [TCPInterface](tcp.md) | `client.TCP()` | Forward TCP connections to sandbox ports |
| [ConfigInterface](config.md) | `client.Config()` | Read and update sandbox and gateway configuration |
| [PolicyInterface](policy.md) | `client.Policy()` | Manage draft policy recommendations |

### Convenience Packages

| Package | Entry Point | Description |
|---------|-------------|-------------|
| [gateway](gateway.md) | `gateway.NewClient(name)` | Read CLI gateway configs and auto-wire clients |

### Provider Sub-Interfaces

These are accessed through `client.Providers()`:

| Interface | Accessor | Description |
|-----------|----------|-------------|
| [ProfileInterface](profiles.md) | `client.Providers().Profiles()` | Manage provider type profiles |
| [RefreshInterface](refresh.md) | `client.Providers().Refresh()` | Configure credential refresh strategies |

## Interfaces

Each interface has a reference page with method signatures and usage examples:

- **[Sandboxes](sandboxes.md)**: Create sandboxes, wait for readiness, watch state changes, manage providers, retrieve logs.
- **[Exec](exec.md)**: Execute commands with one-shot, streaming, or interactive modes.
- **[Providers](providers.md)**: Register and manage compute providers. Includes sub-clients for profiles and credential refresh.
- **[Services](services.md)**: Expose and manage HTTP services inside sandboxes.
- **[Files](files.md)**: Upload and download files to/from sandboxes.
- **[Health](health.md)**: Check gateway health status.
- **[SSH](ssh.md)**: Create SSH sessions and tunnels to sandboxes.
- **[TCP](tcp.md)**: Forward TCP connections to sandbox ports.
- **[Config](config.md)**: Read and update sandbox and gateway configuration.
- **[Policy](policy.md)**: Manage draft policy recommendations.
- **[Profiles](profiles.md)**: Manage provider type profiles (via `client.Providers().Profiles()`).
- **[Refresh](refresh.md)**: Configure credential refresh strategies (via `client.Providers().Refresh()`).

## Common Patterns

All SDK methods follow these conventions:

- Every method takes `context.Context` as its first argument
- Methods that can fail return `(result, error)`
- List methods accept variadic option arguments
- Errors from the gateway carry a `StatusError` with a typed code (see [Error Handling](../error-handling.md))
