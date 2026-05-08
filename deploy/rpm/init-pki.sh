#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Generate a self-signed PKI bundle for the OpenShell gateway.
#
# Called from the systemd ExecStartPre directive to bootstrap mTLS on
# first start. Idempotent: exits immediately if all cert files exist.
# Detects and recovers from partial PKI state (e.g. interrupted runs).
#
# All files are generated in a temporary staging directory first and
# moved into place only after the full PKI is complete, preventing
# partial state from persisting across failures.
#
# Usage:
#   init-pki.sh <pki-dir>
#
# Output layout:
#   <pki-dir>/ca.crt           CA certificate
#   <pki-dir>/ca.key           CA private key (mode 0600)
#   <pki-dir>/server/tls.crt   Server certificate
#   <pki-dir>/server/tls.key   Server private key (mode 0600)
#   <pki-dir>/client/tls.crt   Client certificate
#   <pki-dir>/client/tls.key   Client private key (mode 0600)
#
# Client certs are also copied to the CLI's auto-discovery directory:
#   $XDG_CONFIG_HOME/openshell/gateways/openshell/mtls/{ca.crt,tls.crt,tls.key}

set -euo pipefail

PKI_DIR="${1:?Usage: init-pki.sh <pki-dir>}"

# ── Resolve CLI cert directory ───────────────────────────────────────
CLI_MTLS_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/openshell/gateways/openshell/mtls"

# ── Required PKI files ───────────────────────────────────────────────
PKI_FILES=(
    "${PKI_DIR}/ca.crt"
    "${PKI_DIR}/ca.key"
    "${PKI_DIR}/server/tls.crt"
    "${PKI_DIR}/server/tls.key"
    "${PKI_DIR}/client/tls.crt"
    "${PKI_DIR}/client/tls.key"
)

CLI_FILES=(
    "${CLI_MTLS_DIR}/ca.crt"
    "${CLI_MTLS_DIR}/tls.crt"
    "${CLI_MTLS_DIR}/tls.key"
)

# ── Idempotent: skip if all PKI files exist ──────────────────────────
all_pki_exist=true
for f in "${PKI_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        all_pki_exist=false
        break
    fi
done

if [ "$all_pki_exist" = true ]; then
    # PKI is complete. Ensure CLI copies also exist (they may have been
    # deleted independently, e.g. user cleared their config directory).
    cli_ok=true
    for f in "${CLI_FILES[@]}"; do
        if [ ! -f "$f" ]; then
            cli_ok=false
            break
        fi
    done
    if [ "$cli_ok" = false ]; then
        echo "PKI exists but CLI auto-discovery certs missing; re-copying..."
        mkdir -p "${CLI_MTLS_DIR}"
        cp "${PKI_DIR}/ca.crt" "${CLI_MTLS_DIR}/ca.crt"
        cp "${PKI_DIR}/client/tls.crt" "${CLI_MTLS_DIR}/tls.crt"
        cp "${PKI_DIR}/client/tls.key" "${CLI_MTLS_DIR}/tls.key"
        chmod 600 "${CLI_MTLS_DIR}/tls.key"
    fi
    exit 0
fi

# ── Partial state recovery ───────────────────────────────────────────
# If some PKI files exist but not all, a previous run was interrupted.
# Remove the partial state so we can regenerate cleanly.
partial=false
for f in "${PKI_FILES[@]}"; do
    if [ -f "$f" ]; then
        partial=true
        break
    fi
done
if [ "$partial" = true ]; then
    echo "WARNING: Partial PKI detected in ${PKI_DIR}, regenerating..."
    rm -f "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key" "${PKI_DIR}/ca.srl"
    rm -rf "${PKI_DIR}/server" "${PKI_DIR}/client"
fi

# ── Temporary workspace (cleaned up on exit) ─────────────────────────
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT

# Stage directory mirrors the final PKI layout.
STAGE="${WORK}/pki"
mkdir -p "${STAGE}/server" "${STAGE}/client"

# ── Server certificate SANs ─────────────────────────────────────────
# These must match what the supervisor connects to. The CLI also
# connects using localhost/127.0.0.1 by default.
cat > "${WORK}/server-san.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
O = openshell
CN = openshell-server

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = openshell
DNS.3 = openshell.openshell.svc
DNS.4 = openshell.openshell.svc.cluster.local
DNS.5 = host.containers.internal
DNS.6 = host.docker.internal
IP.1 = 127.0.0.1
EOF

# ── Generate CA (into staging) ───────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${STAGE}/ca.key" \
    -out "${STAGE}/ca.crt" \
    -days 3650 -nodes \
    -subj "/O=openshell/CN=openshell-ca" \
    2>/dev/null
chmod 600 "${STAGE}/ca.key"

# ── Generate server certificate (into staging) ───────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${STAGE}/server/tls.key" \
    -out "${WORK}/server.csr" \
    -nodes \
    -config "${WORK}/server-san.cnf" \
    2>/dev/null

openssl x509 -req \
    -in "${WORK}/server.csr" \
    -CA "${STAGE}/ca.crt" -CAkey "${STAGE}/ca.key" -CAcreateserial \
    -out "${STAGE}/server/tls.crt" \
    -days 3650 \
    -extensions v3_req \
    -extfile "${WORK}/server-san.cnf" \
    2>/dev/null
chmod 600 "${STAGE}/server/tls.key"

# ── Generate client certificate (into staging) ───────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${STAGE}/client/tls.key" \
    -out "${WORK}/client.csr" \
    -nodes \
    -subj "/O=openshell/CN=openshell-client" \
    2>/dev/null

openssl x509 -req \
    -in "${WORK}/client.csr" \
    -CA "${STAGE}/ca.crt" -CAkey "${STAGE}/ca.key" -CAcreateserial \
    -out "${STAGE}/client/tls.crt" \
    -days 3650 \
    2>/dev/null
chmod 600 "${STAGE}/client/tls.key"

# ── Move staged PKI into final location ──────────────────────────────
# Create parent directories and move files individually. Using mv on
# individual files rather than whole directories so we do not clobber
# the target directory if it already exists.
mkdir -p "${PKI_DIR}/server" "${PKI_DIR}/client"
mv "${STAGE}/ca.crt" "${PKI_DIR}/ca.crt"
mv "${STAGE}/ca.key" "${PKI_DIR}/ca.key"
mv "${STAGE}/server/tls.crt" "${PKI_DIR}/server/tls.crt"
mv "${STAGE}/server/tls.key" "${PKI_DIR}/server/tls.key"
mv "${STAGE}/client/tls.crt" "${PKI_DIR}/client/tls.crt"
mv "${STAGE}/client/tls.key" "${PKI_DIR}/client/tls.key"

# ── Copy client certs to CLI auto-discovery directory ────────────────
# The CLI automatically looks for certs at:
#   $XDG_CONFIG_HOME/openshell/gateways/<name>/mtls/{ca.crt,tls.crt,tls.key}
# For localhost gateways, <name> defaults to "openshell".
mkdir -p "${CLI_MTLS_DIR}"
cp "${PKI_DIR}/ca.crt" "${CLI_MTLS_DIR}/ca.crt"
cp "${PKI_DIR}/client/tls.crt" "${CLI_MTLS_DIR}/tls.crt"
cp "${PKI_DIR}/client/tls.key" "${CLI_MTLS_DIR}/tls.key"
chmod 600 "${CLI_MTLS_DIR}/tls.key"

echo "PKI bootstrap complete: ${PKI_DIR}"
