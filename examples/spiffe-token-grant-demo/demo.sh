#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_FILE="${SCRIPT_DIR}/provider-profile.yaml"
K8S_DIR="${SCRIPT_DIR}/k8s"

SANDBOX_NAME="${SANDBOX_NAME:-spiffe-token-demo}"
PROVIDER_NAME="${PROVIDER_NAME:-spiffe-token-demo}"
PROFILE_ID="${PROFILE_ID:-spiffe-token-demo}"
PORT_FORWARD_PORT="${PORT_FORWARD_PORT:-8097}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-http://127.0.0.1:${PORT_FORWARD_PORT}}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
ACCESS_TOKEN_SECRET="${ACCESS_TOKEN_SECRET:-$(openssl rand -hex 32)}"

TEMP_CONFIG_HOME=""
if [[ -z "${XDG_CONFIG_HOME:-}" ]]; then
    TEMP_CONFIG_HOME="$(mktemp -d)"
    export XDG_CONFIG_HOME="$TEMP_CONFIG_HOME"
fi

PF_PID=""

cleanup() {
    if [[ "$KEEP_SANDBOX" != "1" ]]; then
        openshell --gateway-endpoint "$GATEWAY_ENDPOINT" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$PF_PID" ]]; then
        kill "$PF_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TEMP_CONFIG_HOME" ]]; then
        rm -rf "$TEMP_CONFIG_HOME"
    fi
}
trap cleanup EXIT

run() {
    printf "\n$ %s\n" "$*"
    "$@"
}

wait_for_port_forward() {
    for _ in $(seq 1 60); do
        if nc -z 127.0.0.1 "$PORT_FORWARD_PORT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    printf "gateway port-forward did not become ready\n" >&2
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

OS=(openshell --gateway-endpoint "$GATEWAY_ENDPOINT")

printf "\n$ kubectl -n default create secret generic openshell-spiffe-token-demo --from-literal=access-token-secret=*** --dry-run=client -o yaml | kubectl apply -f -\n"
kubectl -n default create secret generic openshell-spiffe-token-demo \
    --from-literal=access-token-secret="$ACCESS_TOKEN_SECRET" \
    --dry-run=client \
    -o yaml | kubectl apply -f -

run kubectl apply -k "$K8S_DIR"
run kubectl -n default rollout restart deployment/token-issuer deployment/alpha deployment/beta
run kubectl -n default rollout status deployment/token-issuer --timeout=180s
run kubectl -n default rollout status deployment/alpha --timeout=180s
run kubectl -n default rollout status deployment/beta --timeout=180s

kubectl -n openshell port-forward svc/openshell "${PORT_FORWARD_PORT}:8080" >/tmp/openshell-spiffe-token-demo-port-forward.log 2>&1 &
PF_PID=$!
wait_for_port_forward

"${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider delete "$PROVIDER_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider profile delete "$PROFILE_ID" >/dev/null 2>&1 || true

run "${OS[@]}" settings set --global --key providers_v2_enabled --value true --yes
run "${OS[@]}" provider profile lint -f "$PROFILE_FILE"
run "${OS[@]}" provider profile import -f "$PROFILE_FILE"
run "${OS[@]}" provider create --name "$PROVIDER_NAME" --type "$PROFILE_ID" --runtime-credentials
run "${OS[@]}" sandbox create --name "$SANDBOX_NAME" --provider "$PROVIDER_NAME" --no-tty -- echo "sandbox ready"

sandbox_curl_until "alpha" "http://alpha.default.svc.cluster.local/" "alpha called with path /:"
ALPHA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$ALPHA_OUTPUT" "alpha called with path /:"
assert_contains "$ALPHA_OUTPUT" "aud: alpha, account"
assert_contains "$ALPHA_OUTPUT" "scope: alpha profile email"
assert_contains "$ALPHA_OUTPUT" "azp: spiffe://openshell.local/openshell/sandbox/"

sandbox_curl_until "beta" "http://beta.default.svc.cluster.local/" "beta called with path /:"
BETA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$BETA_OUTPUT" "beta called with path /:"
assert_contains "$BETA_OUTPUT" "aud: beta, account"
assert_contains "$BETA_OUTPUT" "scope: beta profile email"
assert_contains "$BETA_OUTPUT" "azp: spiffe://openshell.local/openshell/sandbox/"

sleep 1

printf "\n$ kubectl -n default logs -l app=alpha --tail=20 --prefix=true\n"
kubectl -n default logs -l app=alpha --tail=20 --prefix=true | sed 's/^/alpha> /'

printf "\n$ kubectl -n default logs -l app=beta --tail=20 --prefix=true\n"
kubectl -n default logs -l app=beta --tail=20 --prefix=true | sed 's/^/beta> /'

printf "\nSPIFFE token grant demo succeeded.\n"
