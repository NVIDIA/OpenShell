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
exist (the unit has built-in defaults for all required settings except
the SSH handshake secret).

# VARIABLES

## Required

**OPENSHELL_SSH_HANDSHAKE_SECRET**
:   Shared HMAC secret for gateway-to-sandbox SSH handshake
    authentication. Auto-generated as a 32-byte hex string on first
    start. To regenerate: **openssl rand -hex 32**.

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

**OPENSHELL_DISABLE_GATEWAY_AUTH** (default: unset)
:   Set to **true** to disable mTLS client certificate verification.

## TLS

**OPENSHELL_TLS_CERT** (default: auto-generated path)
:   Path to server TLS certificate.

**OPENSHELL_TLS_KEY** (default: auto-generated path)
:   Path to server TLS private key.

**OPENSHELL_TLS_CLIENT_CA** (default: auto-generated path)
:   Path to CA certificate for client certificate verification.

**OPENSHELL_DISABLE_TLS** (default: unset)
:   Set to **true** to disable TLS entirely and listen on plaintext
    HTTP. Not recommended for production. When the bind address is
    **0.0.0.0** (the RPM default), disabling TLS exposes the API to the
    entire network without authentication. Restrict
    **OPENSHELL_BIND_ADDRESS** to **127.0.0.1** or place the gateway
    behind a TLS-terminating reverse proxy.

**OPENSHELL_PODMAN_TLS_CA** (default: auto-generated path)
:   CA certificate bind-mounted into sandbox containers.

**OPENSHELL_PODMAN_TLS_CERT** (default: auto-generated path)
:   Client certificate bind-mounted into sandbox containers.

**OPENSHELL_PODMAN_TLS_KEY** (default: auto-generated path)
:   Client private key bind-mounted into sandbox containers.

## Images

**OPENSHELL_SUPERVISOR_IMAGE** (default: ghcr.io/nvidia/openshell/supervisor:latest)
:   OCI image containing the supervisor binary, mounted read-only
    into sandbox containers.

**OPENSHELL_SANDBOX_IMAGE** (default: ghcr.io/nvidia/openshell-community/sandboxes/base:latest)
:   Default OCI image for sandbox containers.

**OPENSHELL_SANDBOX_IMAGE_PULL_POLICY** (default: missing)
:   When to pull sandbox images: **always** (every sandbox creation),
    **missing** (only if not cached locally), **never** (use cached
    only), **newer** (pull if a newer version exists).

## Podman Driver

**OPENSHELL_PODMAN_SOCKET** (default: $XDG_RUNTIME_DIR/podman/podman.sock)
:   Path to the Podman API Unix socket.

**OPENSHELL_NETWORK_NAME** (default: openshell)
:   Name of the Podman bridge network for sandbox containers. Created
    automatically if it does not exist.

**OPENSHELL_STOP_TIMEOUT** (default: 10)
:   Seconds to wait after SIGTERM before sending SIGKILL when stopping
    a sandbox container.

# EXAMPLES

Change the API port to 9090:

    OPENSHELL_SERVER_PORT=9090

Pin sandbox images to a specific version:

    OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:v0.0.37
    OPENSHELL_SANDBOX_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:v0.0.37

Air-gapped deployment (pre-loaded images, no registry access):

    OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=never

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
