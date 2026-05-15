---
title: OPENSHELL-GATEWAY.ENV
section: 5
header: OpenShell Manual
footer: openshell-gateway
date: 2025
---

# NAME

openshell-gateway.env - OpenShell gateway environment configuration

# DESCRIPTION

The **openshell-gateway.env** file contains environment variables that
configure the OpenShell gateway server when running as a systemd user
service. It is generated automatically on first start by
**init-gateway-env.sh** and is not overwritten on subsequent starts or
package upgrades.

The file uses the standard systemd **EnvironmentFile** format: one
**KEY=VALUE** pair per line. Lines beginning with **#** are comments.
Shell variable expansion is not performed.

# LOCATION

The file is located at:

    ~/.config/openshell/gateway.env

The systemd user unit reads it via:

    EnvironmentFile=-~/.config/openshell/gateway.env

The **-** prefix means the service starts normally if the file does not
exist (the unit has built-in defaults for all required settings).

# VARIABLES

## Gateway

**OPENSHELL_BIND_ADDRESS** (default: 0.0.0.0)
:   IP address to bind all listeners to. The RPM default of **0.0.0.0**
    exposes the gateway on all network interfaces; mTLS must remain
    enabled to prevent unauthenticated access. Set to **127.0.0.1** for
    local-only access.

**OPENSHELL_SERVER_PORT** (default: 8080)
:   Port for the multiplexed gRPC/HTTP API.

**OPENSHELL_HEALTH_PORT** (default: 0)
:   Port for unauthenticated health endpoints (/healthz, /readyz).
    Set to a non-zero value to enable a dedicated health listener.

**OPENSHELL_METRICS_PORT** (default: 0)
:   Port for Prometheus metrics endpoint (/metrics). Set to a
    non-zero value to enable a dedicated metrics listener.

**OPENSHELL_LOG_LEVEL** (default: info)
:   Log verbosity: **trace**, **debug**, **info**, **warn**, **error**.

**OPENSHELL_DRIVERS** (default: podman)
:   Compute driver for sandbox management. Options: **podman**,
    **docker**, **kubernetes**. The RPM unit defaults to **podman**.

**OPENSHELL_DB_URL** (default: sqlite://$XDG_STATE_HOME/openshell/gateway.db)
:   SQLite database URL for gateway state persistence.

## TLS

**OPENSHELL_TLS_CERT** (default: auto-generated path)
:   Path to server TLS certificate.

**OPENSHELL_TLS_KEY** (default: auto-generated path)
:   Path to server TLS private key.

**OPENSHELL_TLS_CLIENT_CA** (default: auto-generated path)
:   Path to CA certificate for client certificate verification. When
    set without **OPENSHELL_OIDC_ISSUER**, mTLS is required. When both
    are set, callers may authenticate via Bearer token or client
    certificate.

**OPENSHELL_DISABLE_TLS** (default: unset)
:   Set to **true** to disable TLS entirely and listen on plaintext
    HTTP. Not recommended for production. When the bind address is
    **0.0.0.0** (the RPM default), disabling TLS exposes the API to the
    entire network without authentication. Restrict
    **OPENSHELL_BIND_ADDRESS** to **127.0.0.1** or place the gateway
    behind a TLS-terminating reverse proxy.

**OPENSHELL_SERVER_SAN** (default: unset)
:   Comma-separated SANs configured on the gateway server certificate.
    Wildcard DNS SANs also enable sandbox service URLs under that
    domain.

## Driver Configuration

Compute driver settings are configured in the TOML file referenced by
**OPENSHELL_GATEWAY_CONFIG** or **--config**. This includes sandbox
images, image pull policy, callback endpoints, Podman socket path,
Docker network name, VM state directory, and guest TLS material.

# EXAMPLES

Change the API port to 9090:

    OPENSHELL_SERVER_PORT=9090

Enable debug logging:

    OPENSHELL_LOG_LEVEL=debug

Use externally-managed TLS certificates:

    OPENSHELL_TLS_CERT=/etc/pki/tls/certs/openshell.crt
    OPENSHELL_TLS_KEY=/etc/pki/tls/private/openshell.key
    OPENSHELL_TLS_CLIENT_CA=/etc/pki/tls/certs/openshell-ca.crt

Disable TLS (behind a reverse proxy):

    OPENSHELL_DISABLE_TLS=true

# SEE ALSO

**openshell-gateway**(8), **openshell**(1), **systemd.exec**(5)

Full documentation: *https://docs.nvidia.com/openshell/*
