# Sandbox

A sandbox is the runtime boundary where agent code executes. It is created by a
compute runtime and managed inside the workload by `openshell-sandbox`, the
sandbox supervisor.

## Runtime Model

Each sandbox workload has two trust levels:

| Process | Role |
|---|---|
| Supervisor | Starts as root inside the workload, prepares isolation, runs the proxy, fetches config, injects credentials, serves the relay socket, and launches child processes. |
| Agent child | Runs as an unprivileged user with filesystem, process, and network restrictions applied. |

The supervisor keeps enough privilege to manage the sandbox, but the agent child
loses that privilege before user code runs.

## Startup Flow

1. The compute runtime starts the workload with sandbox identity, callback
   endpoint, TLS or secret material, image metadata, and initial command.
2. The supervisor loads policy and runtime settings from local files or the
   gateway, depending on mode.
3. It prepares filesystem access, process restrictions, network namespace
   routing, trust stores, provider credential resolution, and inference routes.
4. It starts the policy proxy and local SSH server.
5. It opens a supervisor session back to the gateway for connect, exec, file
   sync, config polling, and log push.
6. It launches the agent command as the restricted sandbox user.

## Isolation Layers

OpenShell uses overlapping controls rather than a single sandbox primitive:

| Layer | Purpose |
|---|---|
| Filesystem policy | Landlock restricts the paths the agent can read or write. |
| Process policy | The child process runs as a non-root user with reduced privileges. |
| Seccomp | Blocks dangerous syscalls, including raw socket paths that bypass the proxy. |
| Network namespace | Forces ordinary agent egress through the local CONNECT proxy. |
| Policy proxy | Evaluates destination, binary identity, TLS/L7 rules, SSRF checks, and inference interception. |

The supervisor may enrich baseline filesystem allowances for runtime-required
paths, such as proxy support files or GPU device paths when a GPU is present.

## Network and Inference

All ordinary agent egress is routed through the sandbox proxy. The proxy
identifies the calling binary, checks trust-on-first-use binary identity, rejects
unsafe internal destinations, and evaluates the active policy.

`https://inference.local` is special. It bypasses OPA network policy and is
handled by the inference interception path:

1. The proxy terminates the local TLS connection with the sandbox CA.
2. It detects known OpenAI, Anthropic, and compatible inference request shapes.
3. It strips caller-supplied credentials and disallowed headers.
4. It forwards through `openshell-router` using the route bundle fetched from
   the gateway.

External inference endpoints that do not use `inference.local` are treated like
ordinary network traffic and must be allowed by policy.

## Credentials

Provider credentials are stored at the gateway and fetched by the supervisor at
runtime. The supervisor injects resolved environment variables into the initial
agent process and SSH child processes. Driver-controlled environment variables
override template values so sandbox images cannot spoof identity, callback, or
relay settings.

Credential placeholders in proxied HTTP requests can be resolved by the proxy
when policy allows the target endpoint. Secrets must not be logged in OCSF or
plain tracing output.

### Selective Passthrough

The canonical placeholder model breaks for credentials that an SDK validates
in-process before any network call (Slack `xoxb-`/`xapp-`, JWT structure,
AWS access-key format), are sent over transports the L7 proxy cannot rewrite
(WebSocket payloads after `101 Switching Protocols`), or are consumed by
in-process crypto (HMAC signing, signature verification).

For these cases an operator can opt specific credential keys into passthrough
via `Provider.passthrough_credentials`. The supervisor injects the real value
into the agent's environment instead of the canonical
`openshell:resolve:env:<KEY>` placeholder, and the resolver does not register
that key, so the L7 proxy performs no substitution for it. Each entry must be
a valid env-var name, present in `Provider.credentials`, and unique. On update,
an empty incoming list preserves the existing list while auto-pruning entries
whose credential was deleted in the same update; a non-empty list replaces the
stored list verbatim. When two providers declare the same credential key, the
first provider's value wins and the passthrough flag follows the winning value.

Passthrough drops the "agent never sees the real secret" invariant for the
listed keys: the real value is at rest in `/proc/<agent-pid>/environ` and any
descendant inherits it. Prefer canonical placeholders; only opt in keys whose
consumer demonstrably fails with the placeholder.

## Connect and Logs

The supervisor runs an SSH server on a Unix socket inside the sandbox. The
gateway reaches it through the outbound supervisor relay, not by dialing the
sandbox workload directly. The relay supports:

- Interactive shell sessions.
- Command execution.
- Tar-based file sync.
- Port forwarding where supported by the CLI/TUI surface.

Sandbox logs are emitted locally and can also be pushed back to the gateway.
Security-relevant sandbox behavior uses OCSF structured events; internal
diagnostics use ordinary tracing.

## Failure Behavior

- If gateway config polling fails, the sandbox keeps its last-known-good policy.
- If a live policy update is invalid, the supervisor rejects it and keeps the
  current policy.
- Existing raw byte streams are connection scoped. Dynamic policy changes apply
  to new connections or the next parsed HTTP request where the proxy can safely
  re-evaluate.
- If the supervisor relay drops, the sandbox can keep running, but connect and
  exec operations fail until the supervisor registers again.
