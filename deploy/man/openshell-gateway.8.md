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

**openshell-gateway config detect-driver**

**openshell-gateway config set** \[*--config PATH*\]
*KEY=VALUE* \[*KEY=VALUE* ...\]

# DESCRIPTION

**openshell-gateway** is the control-plane server for OpenShell. It
manages sandbox lifecycle, stores provider credentials, delivers
network and filesystem policies to sandboxes, routes inference
requests, and provides the SSH tunnel endpoint for CLI-to-sandbox
connections.

When installed via a Linux package, the gateway runs as a systemd user
service. The packaged service starts from built-in defaults and reads
the default gateway TOML path only when that file exists.

The gateway exposes a single port with multiplexed gRPC and HTTP,
secured by mutual TLS (mTLS) by default unless the TOML config disables
TLS.

# OPTIONS

**--bind-address** *IP*
:   IP address to bind all listeners to. Default: **127.0.0.1**.
    Environment: **OPENSHELL_BIND_ADDRESS**.

**--port** *PORT*
:   Port for the gRPC/HTTP API. Default: **17670**.
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
:   SQLite database URL for state persistence. When unset, the gateway
    stores SQLite state under *~/.local/state/openshell/gateway/*.
    Environment: **OPENSHELL_DB_URL**.

**--drivers** *DRIVER*\[,*DRIVER*\]
:   Compute driver. Accepts a comma-delimited list. The gateway
    currently requires exactly one driver. Options: **podman**,
    **docker**, **kubernetes**, **vm**. When unset, the gateway
    auto-detects Kubernetes, then Podman, then Docker. VM is opt-in.
    Environment: **OPENSHELL_DRIVERS**.

**--tls-cert** *PATH*
:   Path to server TLS certificate file. Defaults to the local generated
    TLS bundle when present. Required unless **--disable-tls** is set.
    Environment: **OPENSHELL_TLS_CERT**.

**--tls-key** *PATH*
:   Path to server TLS private key file. Defaults to the local generated
    TLS bundle when present. Required unless **--disable-tls** is set.
    Environment: **OPENSHELL_TLS_KEY**.

**--tls-client-ca** *PATH*
:   Path to CA certificate for client certificate verification (mTLS).
    When set without **--oidc-issuer**, client certificates are required
    and the TLS handshake rejects unauthenticated connections. When set
    together with **--oidc-issuer**, client certificates are accepted
    but not required. Client certificates can authenticate local
    single-user CLI callers when mTLS auth is enabled; sandbox
    supervisors still authenticate with gateway-minted bearer tokens.
    Environment: **OPENSHELL_TLS_CLIENT_CA**.

**--enable-mtls-auth** *BOOL*
:   Enable mTLS client certificate authentication for local single-user
    Docker, Podman, and VM gateways. Defaults on for local gateways with
    client certificate verification and no OIDC issuer. Not supported with
    the Kubernetes compute driver.
    Environment: **OPENSHELL_ENABLE_MTLS_AUTH**.

**--disable-tls**
:   Disable TLS entirely and listen on plaintext HTTP. When the bind
    address is **0.0.0.0**, disabling TLS exposes the API to the entire
    network without authentication. Only use when the gateway sits behind a
    TLS-terminating reverse proxy. The RPM default is **127.0.0.1**.
    Environment: **OPENSHELL_DISABLE_TLS**.

**--server-san** *SAN*
:   Subject Alternative Name configured on the gateway server
    certificate. Repeat or pass a comma-separated value through
    **OPENSHELL_SERVER_SAN**. Wildcard DNS SANs also enable sandbox
    service URLs under that domain.
    Environment: **OPENSHELL_SERVER_SAN**.

Compute driver settings such as sandbox image, callback endpoint, image
pull policy, network name, VM state directory, and guest TLS material are
configured in the TOML file passed with **--config**.

# CONFIG SUBCOMMAND

**openshell-gateway config detect-driver** runs the same automatic driver
detection as gateway startup and prints one value: **kubernetes**, **podman**,
**docker**, or **none**. It does not detect the opt-in VM driver, read the
gateway configuration, or change system state.

**openshell-gateway config set** updates the gateway TOML file without
discarding comments or unrelated settings. It creates the default XDG config
file when needed, validates the complete result, and replaces the file
atomically. Each argument uses a dotted TOML key. TOML booleans, integers,
arrays, and quoted strings retain their types; other unquoted values are
stored as strings. Multiple assignments are applied in one transaction.

*KEY=VALUE*
:   Set a field by its dotted TOML path. Repeat to update multiple fields.
    Set **openshell.gateway.compute_drivers=[]** to restore automatic driver
    selection.

**--config** *PATH*
:   Update a specific gateway TOML file instead of the default XDG location.
    Environment: **OPENSHELL_GATEWAY_CONFIG**.

# SYSTEMD INTEGRATION

The package installs a systemd user unit at
*/usr/lib/systemd/user/openshell-gateway.service*. Manage the gateway
with standard systemd commands:

    systemctl --user enable --now openshell-gateway
    systemctl --user status openshell-gateway
    systemctl --user restart openshell-gateway
    systemctl --user stop openshell-gateway

View logs:

    journalctl --user -u openshell-gateway
    journalctl --user -u openshell-gateway -f

The unit runs **openshell-gateway generate-certs** as an **ExecStartPre**
step on first start. This generates a self-signed PKI bundle for mTLS
and sandbox JWT signing material, adding missing JWT files to older
TLS-only installs when needed. The packaged unit sets
**OPENSHELL_LOCAL_TLS_DIR** to *~/.local/state/openshell/tls* and uses that
same value for certificate generation and gateway startup. Override
**OPENSHELL_LOCAL_TLS_DIR** in *~/.config/openshell/gateway.env* only if you
need a custom bundle location.

The gateway then starts from built-in defaults and reads
*~/.config/openshell/gateway.toml* when that file exists.

To persist the service across logouts:

    sudo loginctl enable-linger $USER

# CONFIGURATION

The systemd user unit launches the gateway with:

    openshell-gateway

Gateway listener, TLS, database, and compute driver settings have local
defaults. Create *~/.config/openshell/gateway.toml* when you need to
override them. The gateway rejects `database_url` in TOML; set
**OPENSHELL_DB_URL** when you need a different database.

To override individual settings without creating TOML:

    systemctl --user edit openshell-gateway

This creates a drop-in override that persists across package upgrades.

# FILES

*/usr/bin/openshell-gateway*
:   Gateway binary.

*/usr/lib/systemd/user/openshell-gateway.service*
:   Systemd user unit file.

*~/.config/openshell/gateway.toml*
:   Optional gateway TOML configuration.

*~/.local/state/openshell/tls/*
:   Auto-generated TLS certificates and sandbox JWT signing keys.

*~/.local/state/openshell/gateway/openshell.db*
:   SQLite database for gateway state.

*~/.config/openshell/gateways/openshell/mtls/*
:   Client mTLS certificates for CLI auto-discovery.

# EXAMPLES

Start the gateway as a systemd user service:

    systemctl --user enable --now openshell-gateway

Check gateway health from the CLI:

    openshell gateway add --local https://127.0.0.1:17670
    openshell status

Override the API port in TOML:

    $EDITOR ~/.config/openshell/gateway.toml
    systemctl --user restart openshell-gateway

# SEE ALSO

**openshell**(1), **systemctl**(1), **journalctl**(1), **loginctl**(1),
**podman**(1)

Full documentation: *https://docs.nvidia.com/openshell/*
