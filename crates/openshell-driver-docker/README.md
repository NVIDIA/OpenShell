# openshell-driver-docker

Docker-backed compute driver for local OpenShell gateways.

The driver manages sandbox containers through the local Docker daemon with the
`bollard` client. It is intended for developer environments where Docker is
already available and running Kubernetes would be unnecessary.

## Runtime Model

The gateway runs as a host process. The Docker driver creates one container per
sandbox and starts the `openshell-sandbox` supervisor inside that container. The
supervisor then creates the nested sandbox namespace for the agent process.

Docker containers currently use host networking. This lets a supervisor reach a
gateway bound to `127.0.0.1` without requiring a separate bridge listener, NAT
rule, or userland proxy. The container also receives
`host.openshell.internal -> 127.0.0.1` so local host services have a stable
OpenShell-owned name.

## Container Contract

The driver-controlled container settings are part of the sandbox security
contract:

| Setting | Purpose |
|---|---|
| `user = "0"` | The supervisor needs root inside the container to prepare namespaces, mounts, Landlock, and seccomp. |
| `network_mode = "host"` | Lets the supervisor call back to loopback gateway endpoints. |
| `cap_add` | Grants supervisor-only capabilities required for namespace setup and process inspection. |
| `apparmor=unconfined` | Avoids Docker's default profile blocking required mount operations. |
| `restart_policy = unless-stopped` | Keeps managed sandboxes resumable across daemon or gateway restarts. |
| CDI GPU request | Requests all NVIDIA GPUs when the sandbox spec asks for GPU support and daemon CDI support is detected. |

The agent child process does not retain these supervisor privileges.

## Callback and TLS

`OPENSHELL_ENDPOINT` is injected from the gateway's configured gRPC endpoint
without rewriting. Because the container uses host networking, loopback
endpoints such as `http://127.0.0.1:8080` resolve to the host gateway.

For HTTPS endpoints, the server certificate must include the endpoint host as a
subject alternative name. Docker sandboxes also need the client TLS bundle
mounted into the container and exposed with:

- `OPENSHELL_TLS_CA`
- `OPENSHELL_TLS_CERT`
- `OPENSHELL_TLS_KEY`

HTTP endpoints reject TLS material because the supervisor would not use it.

## Environment Ownership

The driver merges template environment and sandbox spec environment first, then
overwrites security-critical keys:

- `OPENSHELL_ENDPOINT`
- `OPENSHELL_SANDBOX_ID`
- `OPENSHELL_SANDBOX`
- `OPENSHELL_SSH_SOCKET_PATH`
- `OPENSHELL_SANDBOX_COMMAND`
- TLS path variables when HTTPS is enabled

Do not allow sandbox images or templates to override these values.
