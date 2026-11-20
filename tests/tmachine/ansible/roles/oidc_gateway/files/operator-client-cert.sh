#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Make the packaged gateway's client certificate an operator's (OU=operator),
# so testkit, which connects with it, keeps full access when the gateway also
# accepts OIDC users. Runs as an ExecStartPre after `generate-certs`, which may
# have replaced the certificate, and does nothing if it is already an
# operator's. It then copies the certificate where the CLI finds it, since
# `generate-certs` copies its own there on every start.
set -eu

tls_dir=${OPENSHELL_LOCAL_TLS_DIR:?OPENSHELL_LOCAL_TLS_DIR is not set}
ca_cert=$tls_dir/ca.crt
ca_key=$tls_dir/ca.key
cert=$tls_dir/client/tls.crt
key=$tls_dir/client/tls.key

is_operator() {
  openssl verify -CAfile "$ca_cert" "$cert" >/dev/null 2>&1 &&
    openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 | grep -q 'OU=operator'
}

if ! is_operator; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/tls.key"
  openssl req -new -key "$work/tls.key" \
    -subj "/O=openshell/OU=operator/CN=openshell-test-operator" -out "$work/tls.csr"
  cat >"$work/ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
  openssl x509 -req -in "$work/tls.csr" -CA "$ca_cert" -CAkey "$ca_key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 3650 \
    -extfile "$work/ext.cnf" -out "$work/tls.crt"
  install -m 0600 "$work/tls.key" "$key"
  install -m 0644 "$work/tls.crt" "$cert"
  is_operator
fi

cli_dir=${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateways/openshell/mtls
mkdir -p "$cli_dir"
install -m 0644 "$ca_cert" "$cli_dir/ca.crt"
install -m 0644 "$cert" "$cli_dir/tls.crt"
install -m 0600 "$key" "$cli_dir/tls.key"
