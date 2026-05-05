---
title: OPENSHELL-GATEWAY
section: 8
header: OpenShell Manual
footer: openshell-gateway
date: 2025
---

# NAME

openshell-gateway - OpenShell gateway server daemon

# SYNOPSIS

**openshell-gateway** \[*OPTIONS*\]

# DESCRIPTION

**openshell-gateway** is the control-plane server for OpenShell. It
manages sandbox lifecycle, stores provider credentials, delivers
network and filesystem policies to sandboxes, routes inference
requests, and provides the SSH tunnel endpoint for CLI-to-sandbox
connections.

When installed via RPM, the gateway runs as a systemd user service
with the Podman compute driver. Sandboxes are rootless Podman
containers on the host.

The gateway exposes a single port (default 8080) with multiplexed
gRPC and HTTP, secured by mutual TLS (mTLS) by default.

# OPTIONS

**--bind-address** *IP*
:   IP address to bind all listeners to. Default: **127.0.0.1**.
    Environment: **OPENSHELL_BIND_ADDRESS**.

**--port** *PORT*
:   Port for the gRPC/HTTP API. Default: **8080**.
    Environment: **OPENSHELL_SERVER_PORT**.

**--health-port** *PORT*
:   Port for unauthenticated health endpoints (/healthz, /readyz).
    Set to 0 to disable. Default: **0**.
    Environment: **OPENSHELL_HEALTH_PORT**.

**--metrics-port** *PORT*
:   Port for Prometheus metrics (/metrics). Set to 0 to disable.
    Default: **0**. Environment: **OPENSHELL_METRICS_PORT**.

**--log-level** *LEVEL*
:   Log level: trace, debug, info, warn, error. Default: **info**.
    Environment: **OPENSHELL_LOG_LEVEL**.

**--db-url** *URL*
:   SQLite database URL for state persistence. Required.
    Environment: **OPENSHELL_DB_URL**.

**--drivers** *DRIVER*\[,*DRIVER*\]
:   Compute driver. Accepts a comma-delimited list. The gateway
    currently requires exactly one driver. Options: **podman**,
    **docker**, **kubernetes**. Default: **kubernetes**.
    Environment: **OPENSHELL_DRIVERS**.

**--tls-cert** *PATH*
:   Path to server TLS certificate file. Required unless
    **--disable-tls** is set. Environment: **OPENSHELL_TLS_CERT**.

**--tls-key** *PATH*
:   Path to server TLS private key file. Required unless
    **--disable-tls** is set. Environment: **OPENSHELL_TLS_KEY**.

**--tls-client-ca** *PATH*
:   Path to CA certificate for client certificate verification (mTLS).
    Required unless **--disable-tls** is set.
    Environment: **OPENSHELL_TLS_CLIENT_CA**.

**--disable-tls**
:   Disable TLS entirely and listen on plaintext HTTP. When the bind
    address is **0.0.0.0** (the RPM default), disabling TLS exposes the
    API to the entire network without authentication. Only use when the
    gateway sits behind a TLS-terminating reverse proxy, or restrict
    **--bind-address** to **127.0.0.1**.
    Environment: **OPENSHELL_DISABLE_TLS**.

**--disable-gateway-auth**
:   Disable mTLS client certificate requirement. The TLS handshake
    accepts connections without a client certificate. Ignored when
    **--disable-tls** is set.
    Environment: **OPENSHELL_DISABLE_GATEWAY_AUTH**.

**--sandbox-image** *IMAGE*
:   Default container image for sandboxes.
    Environment: **OPENSHELL_SANDBOX_IMAGE**.

**--sandbox-image-pull-policy** *POLICY*
:   Image pull policy: Always, IfNotPresent, Never.
    Environment: **OPENSHELL_SANDBOX_IMAGE_PULL_POLICY**.

**--ssh-handshake-secret** *SECRET*
:   Shared secret for gateway-to-sandbox SSH handshake.
    Environment: **OPENSHELL_SSH_HANDSHAKE_SECRET**.

**--ssh-handshake-skew-secs** *SECONDS*
:   Allowed clock skew in seconds for SSH handshake. Default: **30**.
    Environment: **OPENSHELL_SSH_HANDSHAKE_SKEW_SECS**.

**--ssh-gateway-host** *HOST*
:   Public host for the SSH gateway endpoint. Default: **127.0.0.1**.
    Environment: **OPENSHELL_SSH_GATEWAY_HOST**.

**--ssh-gateway-port** *PORT*
:   Public port for the SSH gateway endpoint. Default: **8080**.
    Environment: **OPENSHELL_SSH_GATEWAY_PORT**.

**--grpc-endpoint** *URL*
:   gRPC endpoint for sandbox callbacks. Should be reachable from
    within sandbox containers.
    Environment: **OPENSHELL_GRPC_ENDPOINT**.

# SYSTEMD INTEGRATION

The RPM installs a systemd user unit at
*/usr/lib/systemd/user/openshell-gateway.service*. Manage the gateway
with standard systemd commands:

    systemctl --user enable --now openshell-gateway
    systemctl --user status openshell-gateway
    systemctl --user restart openshell-gateway
    systemctl --user stop openshell-gateway

View logs:

    journalctl --user -u openshell-gateway
    journalctl --user -u openshell-gateway -f

The unit runs two **ExecStartPre** scripts on first start:

1. **init-pki.sh** generates a self-signed PKI bundle for mTLS.
2. **init-gateway-env.sh** generates the environment configuration
   file with an auto-generated SSH handshake secret.

Both scripts are idempotent and skip generation if their output files
already exist.

To persist the service across logouts:

    sudo loginctl enable-linger $USER

# CONFIGURATION

The systemd user unit reads configuration from
*~/.config/openshell/gateway.env*. See **openshell-gateway.env**(5)
for the full variable reference.

To override individual settings without modifying gateway.env:

    systemctl --user edit openshell-gateway

This creates a drop-in override that persists across package upgrades.

# FILES

*/usr/bin/openshell-gateway*
:   Gateway binary.

*/usr/lib/systemd/user/openshell-gateway.service*
:   Systemd user unit file.

*/usr/libexec/openshell/init-pki.sh*
:   PKI bootstrap script.

*/usr/libexec/openshell/init-gateway-env.sh*
:   Gateway environment file generator.

*~/.config/openshell/gateway.env*
:   Gateway environment configuration (generated on first start).

*~/.local/state/openshell/tls/*
:   Auto-generated TLS certificates.

*~/.local/state/openshell/gateway.db*
:   SQLite database for gateway state.

*~/.config/openshell/gateways/openshell/mtls/*
:   Client mTLS certificates for CLI auto-discovery.

# EXAMPLES

Start the gateway as a systemd user service:

    systemctl --user enable --now openshell-gateway

Check gateway health from the CLI:

    openshell gateway add --local https://127.0.0.1:8080
    openshell status

Override the API port via a systemd drop-in:

    systemctl --user edit openshell-gateway
    # Add: [Service]
    # Add: Environment=OPENSHELL_SERVER_PORT=9090

# SEE ALSO

**openshell**(1), **openshell-gateway.env**(5), **systemctl**(1),
**journalctl**(1), **loginctl**(1), **podman**(1)

Full documentation: *https://docs.nvidia.com/openshell/*
