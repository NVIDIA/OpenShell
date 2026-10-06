---
title: RYNO-GATEWAY
section: 8
header: Ryno Manual
footer: ryno-gateway
date: 2025
---

# NAME

ryno-gateway - Ryno gateway server daemon

# SYNOPSIS

**ryno-gateway** \[*OPTIONS*\]

**ryno-gateway** **config preflight** [**--path** *PATH* | **--** *GATEWAY_ARGS*...]

# DESCRIPTION

**ryno-gateway** is the control-plane server for Ryno. It
manages sandbox lifecycle, stores provider credentials, delivers
network and filesystem policies to sandboxes, manages provider access
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
    Environment: **RYNO_BIND_ADDRESS**.

**--port** *PORT*
:   Port for the gRPC/HTTP API. Default: **17670**.
    Environment: **RYNO_SERVER_PORT**.

**--health-port** *PORT*
:   Port for unauthenticated health endpoints (/healthz, /readyz).
    Set to 0 to disable. Default: **0**.
    Environment: **RYNO_HEALTH_PORT**.

**--metrics-port** *PORT*
:   Port for Prometheus metrics (/metrics). Set to 0 to disable.
    Default: **0**. Environment: **RYNO_METRICS_PORT**.

**--log-level** *LEVEL*
:   Log level: trace, debug, info, warn, error. Default: **info**.
    Environment: **RYNO_LOG_LEVEL**.

**--db-url** *URL*
:   SQLite database URL for state persistence. When unset, the gateway
    stores SQLite state under *~/.local/state/ryno/gateway/*.
    Environment: **RYNO_DB_URL**.

**--compute-driver** *DRIVER*
:   Compute driver. Selects exactly one driver. Options: **podman**,
    **docker**, **kubernetes**, **vm**. When unset, the gateway
    auto-detects Kubernetes, then Podman, then Docker. VM is opt-in.
    Environment: **RYNO_COMPUTE_DRIVER**.

**--tls-cert** *PATH*
:   Path to server TLS certificate file. Defaults to the local generated
    TLS bundle when present. Required unless **--disable-tls** is set.
    Environment: **RYNO_TLS_CERT**.

**--tls-key** *PATH*
:   Path to server TLS private key file. Defaults to the local generated
    TLS bundle when present. Required unless **--disable-tls** is set.
    Environment: **RYNO_TLS_KEY**.

**--tls-client-ca** *PATH*
:   Path to CA certificate for client certificate verification (mTLS).
    When set without **--oidc-issuer**, client certificates are required
    and the TLS handshake rejects unauthenticated connections. When set
    together with **--oidc-issuer**, client certificates are accepted
    but not required. Client certificates can authenticate local
    single-user CLI callers when mTLS auth is enabled; sandbox
    supervisors still authenticate with gateway-minted bearer tokens.
    Environment: **RYNO_TLS_CLIENT_CA**.

**--enable-mtls-auth** *BOOL*
:   Enable mTLS client certificate authentication for local single-user
    Docker, Podman, and VM gateways. Defaults on for local gateways with
    client certificate verification and no OIDC issuer. Not supported with
    the Kubernetes compute driver.
    Environment: **RYNO_ENABLE_MTLS_AUTH**.

**--disable-tls**
:   Disable TLS entirely and listen on plaintext HTTP. When the bind
    address is **0.0.0.0** (the RPM default), disabling TLS exposes the
    API to the entire network without authentication. Only use when the
    gateway sits behind a TLS-terminating reverse proxy, or restrict
    **--bind-address** to **127.0.0.1**.
    Environment: **RYNO_DISABLE_TLS**.

**--server-san** *SAN*
:   Subject Alternative Name configured on the gateway server
    certificate. Repeat or pass a comma-separated value through
    **RYNO_SERVER_SAN**. Wildcard DNS SANs also enable sandbox
    service URLs under that domain.
    Environment: **RYNO_SERVER_SAN**.

Compute driver settings such as sandbox image, callback endpoint, image
pull policy, network name, VM state directory, and guest TLS material are
configured in the TOML file passed with **--config**.

# CONFIGURATION PREFLIGHT

Validate a gateway configuration before starting the daemon:

    ryno-gateway config preflight [--path PATH | -- GATEWAY_ARGS...]

With no path, preflight validates a nonempty RYNO_GATEWAY_CONFIG. If that
variable is unset, it optionally validates an auto-discovered XDG config. The
absence of either config still validates the effective daemon arguments. An explicit missing path, legacy schema-v1
file, invalid TOML, symlink, or nonregular file fails with a nonzero status.
Preflight merges file and environment values and applies read-only startup checks
for selector and socket normalization, registered compute-driver configuration,
rate limits, TLS and mTLS, interceptors, and middleware. When a selected file
omits the selector, it validates configured tables for auto-detectable drivers
without running socket or process-based detection probes. It does not construct a
compute driver or connect to a transport. Preflight never changes the file and
reports that failed input was preserved.

Arguments after **--** replace **--path** mode and are parsed as the exact gateway
daemon invocation. Package wrappers use this form so command-line overrides are
validated before the same arguments reach startup.

An explicitly selected local **vm** driver also checks **mke2fs** or **mkfs.ext4**, **debugfs**, and **e2fsck**. Install e2fsprogs 1.43 or newer with the operating system's package manager, then run preflight with the gateway service's account, working directory, configuration, and environment. The command reports selected executable paths and versions. A restricted service **PATH** can select different tools from an interactive shell; include the installation's bin and sbin directories in that service's environment.

Each executable receives only **-V**, with a five-second deadline and an 8 KiB output limit per stream. Missing, non-executable, unsupported, or failing tools return nonzero status with installation or repair guidance. Preflight creates no images or runtime state and does not start the VM driver. Other drivers do not require these tools. A remote driver endpoint reports that host tool checks were not performed; check a local VM configuration on that host in the driver service's environment.

The Debian and Ubuntu systemd user unit runs preflight before certificate
generation, while retaining its EnvironmentFile and bare ExecStart behavior. The
Snap wrapper replays its effective daemon arguments through preflight. It first
uses a nonempty RYNO_GATEWAY_CONFIG. Otherwise it passes the canonical
SNAP_COMMON/gateway.toml path whenever it exists or is a symlink. A broken symlink
fails preflight before the gateway is started. Correct or manually migrate an
operator-owned v1 file, then run preflight again before restarting the service.

# SYSTEMD INTEGRATION

The package installs a systemd user unit at
*/usr/lib/systemd/user/ryno-gateway.service*. Manage the gateway
with standard systemd commands:

    systemctl --user enable --now ryno-gateway
    systemctl --user status ryno-gateway
    systemctl --user restart ryno-gateway
    systemctl --user stop ryno-gateway

View logs:

    journalctl --user -u ryno-gateway
    journalctl --user -u ryno-gateway -f

The unit runs **ryno-gateway config preflight** and then
**ryno-gateway generate-certs** as **ExecStartPre** steps. Certificate
generation creates a self-signed PKI bundle for mTLS
and sandbox JWT signing material, adding missing JWT files to older
TLS-only installs when needed. The packaged unit sets
**RYNO_LOCAL_TLS_DIR** to *~/.local/state/ryno/tls* and uses that
same value for certificate generation and gateway startup. Override
**RYNO_LOCAL_TLS_DIR** in *~/.config/ryno/gateway.env* only if you
need a custom bundle location.

The gateway then starts from built-in defaults and reads
*~/.config/ryno/gateway.toml* when that file exists.

To persist the service across logouts:

    sudo loginctl enable-linger $USER

# CONFIGURATION

The systemd user unit launches the gateway with:

    ryno-gateway

Gateway listener, TLS, database, and compute driver settings have local
defaults. Create *~/.config/ryno/gateway.toml* when you need to
override them. The gateway rejects `database_url` in TOML; set
**RYNO_DB_URL** when you need a different database.

To override individual settings without creating TOML:

    systemctl --user edit ryno-gateway

This creates a drop-in override that persists across package upgrades.

# FILES

*/usr/bin/ryno-gateway*
:   Gateway binary.

*/usr/lib/systemd/user/ryno-gateway.service*
:   Systemd user unit file.

*~/.config/ryno/gateway.toml*
:   Optional gateway TOML configuration.

*~/.local/state/ryno/tls/*
:   Auto-generated TLS certificates and sandbox JWT signing keys.

*~/.local/state/ryno/gateway/ryno.db*
:   SQLite database for gateway state.

*~/.config/ryno/gateways/ryno/mtls/*
:   Client mTLS certificates for CLI auto-discovery.

# EXAMPLES

Start the gateway as a systemd user service:

    systemctl --user enable --now ryno-gateway

Check gateway health from the CLI:

    ryno gateway add --local https://127.0.0.1:17670
    ryno status

Override the API port in TOML:

    $EDITOR ~/.config/ryno/gateway.toml
    systemctl --user restart ryno-gateway

# SEE ALSO

**ryno**(1), **systemctl**(1), **journalctl**(1), **loginctl**(1),
**podman**(1)

Full documentation: *https://docs.nvidia.com/ryno/*
