# Sandbox Connect Architecture

## Overview

`navigator sandbox connect` opens an SSH session into a running sandbox by tunneling SSH bytes
through the existing multiplexed gateway port. The gateway accepts an HTTP CONNECT request,
authenticates it, then bridges raw TCP to an embedded SSH server inside the sandbox pod.

## Components

- **CLI connect + proxy**: `crates/navigator-cli/src/run.rs`
  - `sandbox connect` requests an SSH session token and launches `ssh` with a ProxyCommand.
  - `ssh-proxy` (top-level) opens the HTTPS/HTTP tunnel and pipes stdin/stdout.
  - For interactive shells, the CLI `exec`s into `ssh` so the SSH client owns the terminal.
- **gRPC session bootstrap**: `proto/navigator.proto`, `crates/navigator-server/src/grpc.rs`
  - `CreateSshSession` issues a sandbox-scoped token and gateway connection info.
  - `RevokeSshSession` marks a token revoked.
- **Gateway tunnel handler**: `crates/navigator-server/src/ssh_tunnel.rs`
  - HTTP CONNECT endpoint (`/connect/ssh`) on the shared gateway port.
  - Validates tokens, sandbox readiness, resolves the target, and streams bytes.
- **Sandbox SSH daemon**: `crates/navigator-sandbox/src/ssh.rs`
  - Embedded SSH server (russh) inside the sandbox pod.
  - Validates a gateway handshake preface before starting SSH.
  - Shells run on a PTY (openpty) with blocking IO threads.
- **Sandbox pod routing**: `crates/navigator-server/src/sandbox/mod.rs`
  - Resolves pod IPs from Kubernetes and injects SSH env vars into the pod template.

## Sync Flow (CLI `sandbox create --sync`)

When `--sync` is set on `nav sandbox create`, the CLI rsyncs local files into the sandbox after
it reaches `Ready` and before any command runs. This is opt-in only and respects gitignore rules.

- **Source selection**: `git ls-files -co --exclude-standard` from the repo root.
- **Transport**: `rsync -az --from0 --files-from=- --relative -e "ssh ..."` over the existing
  SSH proxy tunnel.
- **Destination**: files are copied into `/sandbox` inside the sandbox container.
- **Ordering**: sync runs before `exec` so the command sees the latest files.

## API and Persistence

- **CreateSshSession** returns:
  - `token` (session id), `gateway_host`, `gateway_port`, `gateway_scheme`, `connect_path`.
- **RevokeSshSession** marks a token as revoked.
- **SshSession** records are stored in the persistence layer with sandbox id, creation time,
  and a revoked flag.

## Configuration and Environment

### Server Config (gateway + routing)

- `ssh_gateway_host`, `ssh_gateway_port`, `ssh_connect_path`
- `sandbox_ssh_port`
- `ssh_handshake_secret`, `ssh_handshake_skew_secs`

### Sandbox Env Vars (injected into pods)

- `NAVIGATOR_SSH_LISTEN_ADDR`
- `NAVIGATOR_SSH_HANDSHAKE_SECRET`
- `NAVIGATOR_SSH_HANDSHAKE_SKEW_SECS`

## Connection Flow

```mermaid
sequenceDiagram
  participant CLI as navigator CLI
  participant GRPC as Navigator gRPC
  participant GW as Gateway (CONNECT)
  participant K8S as K8s Pod Resolver
  participant SSHD as Sandbox SSH

  CLI->>GRPC: CreateSshSession(sandbox_id)
  GRPC-->>CLI: token + gateway host/port/path
  CLI->>GW: CONNECT /connect/ssh (X-Sandbox-Id, X-Sandbox-Token)
  GW->>K8S: Resolve sandbox pod IP
  GW->>SSHD: TCP connect to sandbox_ssh_port
  GW->>SSHD: Preface (NSSH1 token ts nonce hmac)
  SSHD-->>GW: OK
  GW<->>CLI: Bidirectional byte stream (SSH)
```

## Tunnel and Handshake Details

- **HTTP CONNECT**
  - Method: `CONNECT`
  - Path: `ssh_connect_path` (default `/connect/ssh`)
  - Headers: `X-Sandbox-Id`, `X-Sandbox-Token`

- **Gateway validation** (`crates/navigator-server/src/ssh_tunnel.rs`)
  - Fetches `SshSession` by token; rejects revoked or mismatched sandbox id.
  - Ensures sandbox exists and is `Ready`.
  - Resolves pod IP if `agent_pod` is present; otherwise uses the sandbox service DNS.
  - Opens TCP to `sandbox_ssh_port` on the resolved target.

- **Gateway-to-sandbox preface**
  - Format: `NSSH1 <token> <timestamp> <nonce> <hmac>`\n
  - HMAC is SHA-256 over `token|timestamp|nonce` with the shared secret.
  - Sandbox verifies timestamp is within `ssh_handshake_skew_secs` and HMAC matches.

## Port Forwarding (`sandbox forward start`)

`nav sandbox forward start <port> <name>` opens a local SSH tunnel so connections to `127.0.0.1:<port>`
on the host are forwarded to `127.0.0.1:<port>` inside the sandbox.

### CLI

- Reuses the same `ProxyCommand` path as `sandbox connect`.
- Invokes OpenSSH with `-N -L <port>:127.0.0.1:<port> sandbox`.
- By default stays attached in foreground until interrupted (Ctrl+C).
- With `-d`/`--background`, SSH forks after auth and the CLI exits. The PID is
  tracked in `~/.config/navigator/forwards/<name>-<port>.pid` along with sandbox id metadata.
- `nav sandbox forward stop <port> <name>` validates PID ownership and then kills a background forward.
- `nav sandbox forward list` shows all tracked forwards.
- `nav sandbox forward stop` and `nav sandbox forward list` are local operations and do not require
  resolving an active cluster.
- `nav sandbox create --forward <port>` starts a background forward before connect/exec, including
  when no trailing command is provided.
- `nav sandbox delete` auto-stops any active forwards for the deleted sandbox.

### Supervisor `direct-tcpip` handling

The sandbox SSH server (`crates/navigator-sandbox/src/ssh.rs`) implements
`channel_open_direct_tcpip` from the russh `Handler` trait.

- **Loopback-only**: only `127.0.0.1`, `localhost`, and `::1` destinations are accepted.
  Non-loopback destinations are rejected (`Ok(false)`) to prevent the sandbox from being
  used as a generic proxy.
- **Bridge**: accepted channels spawn a tokio task that connects a `TcpStream` to the
  target address and uses `copy_bidirectional` between the SSH channel stream and the
  TCP stream.
- No additional state is stored on `SshHandler` — the `Channel<Msg>` object from russh is
  self-contained, so forwarding channels are fully independent of session channels.

### Flow

```mermaid
sequenceDiagram
  participant App as Local Application
  participant SSH as OpenSSH Client
  participant GW as Gateway (CONNECT)
  participant SSHD as Sandbox SSH
  participant SVC as Service in Sandbox

  SSH->>GW: CONNECT /connect/ssh
  GW->>SSHD: TCP + Preface handshake
  SSH->>SSHD: direct-tcpip channel (127.0.0.1:port)
  SSHD->>SVC: TcpStream::connect(127.0.0.1:port)
  App->>SSH: connect to 127.0.0.1:port (local)
  SSH->>SSHD: channel data
  SSHD->>SVC: TCP data
  SVC-->>SSHD: TCP response
  SSHD-->>SSH: channel data
  SSH-->>App: response
```

## Authentication Model

- The SSH server accepts any SSH key or none; the gateway handles authorization.
- Session tokens are scoped to a sandbox and can be revoked.
- The handshake secret prevents direct pod access outside the gateway.

## Failure Modes

- Invalid or revoked token: `401 Unauthorized` from gateway.
- Sandbox not Ready / no pod IP: `412 Precondition Failed` or `502 Bad Gateway`.
- Handshake rejected: gateway logs the failure and closes the tunnel.
