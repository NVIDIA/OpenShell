#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_FILE="${SCRIPT_DIR}/provider-profile.yaml"
K8S_DIR="${SCRIPT_DIR}/k8s"

SANDBOX_NAME="${SANDBOX_NAME:-spiffe-token-exchange-demo}"
PROVIDER_NAME="${PROVIDER_NAME:-spiffe-token-exchange-demo}"
PROFILE_ID="${PROFILE_ID:-spiffe-token-exchange-demo}"
PORT_FORWARD_PORT="${PORT_FORWARD_PORT:-8097}"
TOKEN_ISSUER_PORT="${TOKEN_ISSUER_PORT:-18080}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-https://127.0.0.1:${PORT_FORWARD_PORT}}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
ISOLATED_CONFIG="${ISOLATED_CONFIG:-0}"
ACCESS_TOKEN_SECRET="${ACCESS_TOKEN_SECRET:-$(openssl rand -hex 32)}"

TEMP_CONFIG_HOME=""
if [[ "$ISOLATED_CONFIG" == "1" ]]; then
    TEMP_CONFIG_HOME="$(mktemp -d)"
    export XDG_CONFIG_HOME="$TEMP_CONFIG_HOME"
fi

default_gateway_name() {
    if [[ -n "${GATEWAY_NAME:-}" ]]; then
        printf "%s\n" "$GATEWAY_NAME"
        return
    fi
    if [[ -n "${OPENSHELL_GATEWAY:-}" ]]; then
        printf "%s\n" "$OPENSHELL_GATEWAY"
        return
    fi

    local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    if [[ -s "${config_home}/openshell/active_gateway" ]]; then
        head -n1 "${config_home}/openshell/active_gateway"
        return
    fi
    if [[ -s /etc/openshell/active_gateway ]]; then
        head -n1 /etc/openshell/active_gateway
        return
    fi

    printf "k8s\n"
}

GATEWAY_NAME="$(default_gateway_name)"

PF_PID=""
TOKEN_PF_PID=""

dump_diagnostics() {
    set +e

    printf "\n=== diagnostics: openshell sandbox logs ===\n" >&2
    "${OS[@]}" logs "$SANDBOX_NAME" -n 120 --source sandbox >&2

    printf "\n=== diagnostics: gateway logs ===\n" >&2
    kubectl -n openshell logs -l app.kubernetes.io/name=openshell,app.kubernetes.io/instance=openshell \
        --tail=120 --prefix=true >&2

    printf "\n=== diagnostics: token exchange issuer logs ===\n" >&2
    kubectl -n default logs -l app=token-exchange-issuer --tail=120 --prefix=true >&2

    printf "\n=== diagnostics: alpha logs ===\n" >&2
    kubectl -n default logs -l app=alpha-exchange --tail=60 --prefix=true >&2

    printf "\n=== diagnostics: beta logs ===\n" >&2
    kubectl -n default logs -l app=beta-exchange --tail=60 --prefix=true >&2

    printf "\n=== diagnostics: gateway port-forward log ===\n" >&2
    sed 's/^/gateway-port-forward> /' /tmp/openshell-spiffe-token-exchange-demo-gateway-port-forward.log >&2

    printf "\n=== diagnostics: token issuer port-forward log ===\n" >&2
    sed 's/^/issuer-port-forward> /' /tmp/openshell-spiffe-token-exchange-demo-issuer-port-forward.log >&2
}

cleanup() {
    if [[ "$KEEP_SANDBOX" != "1" ]]; then
        openshell --gateway "$GATEWAY_NAME" --gateway-endpoint "$GATEWAY_ENDPOINT" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$PF_PID" ]]; then
        kill "$PF_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TOKEN_PF_PID" ]]; then
        kill "$TOKEN_PF_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TEMP_CONFIG_HOME" ]]; then
        rm -rf "$TEMP_CONFIG_HOME"
    fi
}

on_exit() {
    local status="$1"
    if [[ "$status" -ne 0 ]]; then
        dump_diagnostics || true
    fi
    cleanup
    exit "$status"
}
trap 'on_exit $?' EXIT

run() {
    printf "\n$ %s\n" "$*"
    "$@"
}

wait_for_port() {
    local port="$1"
    local label="$2"
    for _ in $(seq 1 60); do
        if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    printf "%s port-forward did not become ready\n" "$label" >&2
    exit 1
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "$haystack" != *"$needle"* ]]; then
        printf "expected output to contain: %s\n" "$needle" >&2
        printf "actual output:\n%s\n" "$haystack" >&2
        exit 1
    fi
}

install_gateway_tls_bundle() {
    local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    local tls_dir="${config_home}/openshell/gateways/${GATEWAY_NAME}/mtls"
    mkdir -p "$tls_dir"
    kubectl -n openshell get secret openshell-client-tls \
        -o jsonpath='{.data.ca\.crt}' | base64 -d >"${tls_dir}/ca.crt"
    kubectl -n openshell get secret openshell-client-tls \
        -o jsonpath='{.data.tls\.crt}' | base64 -d >"${tls_dir}/tls.crt"
    kubectl -n openshell get secret openshell-client-tls \
        -o jsonpath='{.data.tls\.key}' | base64 -d >"${tls_dir}/tls.key"
}

subject_token_from_json() {
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

sandbox_curl_until() {
    local label="$1"
    local url="$2"
    local expected="$3"
    local output=""

    for attempt in $(seq 1 12); do
        printf "\n$ openshell sandbox exec %s curl (attempt %s)\n" "$label" "$attempt"
        if output=$("${OS[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- curl -sS --max-time 10 "$url" 2>&1); then
            printf "%s\n" "$output"
            if [[ "$output" == *"$expected"* ]]; then
                SANDBOX_CURL_OUTPUT="$output"
                return 0
            fi
        else
            printf "%s\n" "$output"
        fi
        sleep 2
    done

    printf "timed out waiting for %s to return expected output\n" "$label" >&2
    printf "last output:\n%s\n" "$output" >&2
    exit 1
}

OS=(openshell --gateway "$GATEWAY_NAME" --gateway-endpoint "$GATEWAY_ENDPOINT")

printf "Using OpenShell gateway '%s' at %s\n" "$GATEWAY_NAME" "$GATEWAY_ENDPOINT"

printf "\n$ kubectl -n default create secret generic openshell-spiffe-token-exchange-demo --from-literal=access-token-secret=*** --dry-run=client -o yaml | kubectl apply -f -\n"
kubectl -n default create secret generic openshell-spiffe-token-exchange-demo \
    --from-literal=access-token-secret="$ACCESS_TOKEN_SECRET" \
    --dry-run=client \
    -o yaml | kubectl apply -f -

run kubectl apply -k "$K8S_DIR"
run kubectl -n default rollout restart deployment/token-exchange-issuer deployment/alpha-exchange deployment/beta-exchange
run kubectl -n default rollout status deployment/token-exchange-issuer --timeout=180s
run kubectl -n default rollout status deployment/alpha-exchange --timeout=180s
run kubectl -n default rollout status deployment/beta-exchange --timeout=180s

kubectl -n openshell port-forward svc/openshell "${PORT_FORWARD_PORT}:8080" >/tmp/openshell-spiffe-token-exchange-demo-gateway-port-forward.log 2>&1 &
PF_PID=$!
wait_for_port "$PORT_FORWARD_PORT" "gateway"
install_gateway_tls_bundle

kubectl -n default port-forward svc/token-exchange-issuer "${TOKEN_ISSUER_PORT}:80" >/tmp/openshell-spiffe-token-exchange-demo-issuer-port-forward.log 2>&1 &
TOKEN_PF_PID=$!
wait_for_port "$TOKEN_ISSUER_PORT" "token issuer"

SUBJECT_TOKEN="$(curl -fsS "http://127.0.0.1:${TOKEN_ISSUER_PORT}/demo-subject-token" | subject_token_from_json)"

"${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider delete "$PROVIDER_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider profile delete "$PROFILE_ID" >/dev/null 2>&1 || true

run "${OS[@]}" settings set --global --key providers_v2_enabled --value true --yes
run "${OS[@]}" provider profile lint -f "$PROFILE_FILE"
run "${OS[@]}" provider profile import -f "$PROFILE_FILE"
run "${OS[@]}" provider create --name "$PROVIDER_NAME" --type "$PROFILE_ID" --credential "subject_token=${SUBJECT_TOKEN}"
run "${OS[@]}" sandbox create --name "$SANDBOX_NAME" --provider "$PROVIDER_NAME" --keep --no-tty -- echo "sandbox ready"

sandbox_curl_until "alpha" "http://alpha-exchange.default.svc.cluster.local/" "alpha called with path /:"
ALPHA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$ALPHA_OUTPUT" "alpha called with path /:"
assert_contains "$ALPHA_OUTPUT" "sub: demo-user"
assert_contains "$ALPHA_OUTPUT" "aud: alpha, account"
assert_contains "$ALPHA_OUTPUT" "scope: alpha profile email"
assert_contains "$ALPHA_OUTPUT" "azp: spiffe://openshell.local/openshell/sandbox/"

sandbox_curl_until "beta" "http://beta-exchange.default.svc.cluster.local/" "beta called with path /:"
BETA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$BETA_OUTPUT" "beta called with path /:"
assert_contains "$BETA_OUTPUT" "sub: demo-user"
assert_contains "$BETA_OUTPUT" "aud: beta, account"
assert_contains "$BETA_OUTPUT" "scope: beta profile email"
assert_contains "$BETA_OUTPUT" "azp: spiffe://openshell.local/openshell/sandbox/"

printf "\nSPIFFE token exchange demo succeeded.\n"
