#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Generate a self-signed PKI bundle for the OpenShell gateway.
#
# Called from the systemd ExecStartPre directive to bootstrap mTLS on
# first start. Idempotent: exits immediately if certs already exist.
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

# ── Idempotent: skip if CA already exists ────────────────────────────
if [ -f "${PKI_DIR}/ca.crt" ]; then
    exit 0
fi

# ── Resolve CLI cert directory ───────────────────────────────────────
CLI_MTLS_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/openshell/gateways/openshell/mtls"

# ── Create directories ───────────────────────────────────────────────
mkdir -p "${PKI_DIR}/server" "${PKI_DIR}/client" "${CLI_MTLS_DIR}"

# ── Temporary workspace (cleaned up on exit) ─────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# ── Server certificate SANs ─────────────────────────────────────────
# These must match what the supervisor connects to. The CLI also
# connects using localhost/127.0.0.1 by default.
cat > "${TMPDIR}/server-san.cnf" <<'EOF'
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

# ── Generate CA ──────────────────────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/ca.key" \
    -out "${PKI_DIR}/ca.crt" \
    -days 3650 -nodes \
    -subj "/O=openshell/CN=openshell-ca" \
    2>/dev/null
chmod 600 "${PKI_DIR}/ca.key"

# ── Generate server certificate ──────────────────────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/server/tls.key" \
    -out "${TMPDIR}/server.csr" \
    -nodes \
    -config "${TMPDIR}/server-san.cnf" \
    2>/dev/null

openssl x509 -req \
    -in "${TMPDIR}/server.csr" \
    -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" -CAcreateserial \
    -out "${PKI_DIR}/server/tls.crt" \
    -days 3650 \
    -extensions v3_req \
    -extfile "${TMPDIR}/server-san.cnf" \
    2>/dev/null
chmod 600 "${PKI_DIR}/server/tls.key"

# ── Generate client certificate ──────────────────────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/client/tls.key" \
    -out "${TMPDIR}/client.csr" \
    -nodes \
    -subj "/O=openshell/CN=openshell-client" \
    2>/dev/null

openssl x509 -req \
    -in "${TMPDIR}/client.csr" \
    -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" -CAcreateserial \
    -out "${PKI_DIR}/client/tls.crt" \
    -days 3650 \
    2>/dev/null
chmod 600 "${PKI_DIR}/client/tls.key"

# ── Copy client certs to CLI auto-discovery directory ────────────────
# The CLI automatically looks for certs at:
#   $XDG_CONFIG_HOME/openshell/gateways/<name>/mtls/{ca.crt,tls.crt,tls.key}
# For localhost gateways, <name> defaults to "openshell".
cp "${PKI_DIR}/ca.crt" "${CLI_MTLS_DIR}/ca.crt"
cp "${PKI_DIR}/client/tls.crt" "${CLI_MTLS_DIR}/tls.crt"
cp "${PKI_DIR}/client/tls.key" "${CLI_MTLS_DIR}/tls.key"
chmod 600 "${CLI_MTLS_DIR}/tls.key"

echo "PKI bootstrap complete: ${PKI_DIR}"
