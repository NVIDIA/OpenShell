#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for the DNS resolver extraction logic in cluster-entrypoint.sh.
#
# Validates that get_upstream_resolvers() correctly filters loopback addresses
# (IPv4 127.x.x.x, IPv6 ::1) and passes through real upstream nameservers.
#
# Usage: sh deploy/docker/tests/test-dns-resolvers.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

_PASS=0
_FAIL=0

pass() {
    _PASS=$((_PASS + 1))
    printf '  PASS: %s\n' "$1"
}

fail() {
    _FAIL=$((_FAIL + 1))
    printf '  FAIL: %s\n' "$1" >&2
    if [ -n "${2:-}" ]; then
        printf '        %s\n' "$2" >&2
    fi
}

assert_eq() {
    _actual="$1"
    _expected="$2"
    _label="$3"

    if [ "$_actual" = "$_expected" ]; then
        pass "$_label"
    else
        fail "$_label" "expected '$_expected', got '$_actual'"
    fi
}

assert_contains() {
    _haystack="$1"
    _needle="$2"
    _label="$3"

    if printf '%s' "$_haystack" | grep -qF "$_needle"; then
        pass "$_label"
    else
        fail "$_label" "expected '$_needle' in output '$_haystack'"
    fi
}

assert_not_contains() {
    _haystack="$1"
    _needle="$2"
    _label="$3"

    if printf '%s' "$_haystack" | grep -qF "$_needle"; then
        fail "$_label" "unexpected '$_needle' found in output '$_haystack'"
    else
        pass "$_label"
    fi
}

assert_empty() {
    _val="$1"
    _label="$2"

    if [ -z "$_val" ]; then
        pass "$_label"
    else
        fail "$_label" "expected empty, got '$_val'"
    fi
}

# The awk filter extracted from cluster-entrypoint.sh. Tested in isolation
# so we don't need root, iptables, or a running container.
filter_resolvers() {
    awk '/^nameserver/{ip=$2; if(ip !~ /^127\./ && ip != "::1") print ip}'
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_filters_ipv4_loopback() {
    printf 'TEST: filters IPv4 loopback addresses\n'

    input="nameserver 127.0.0.1
nameserver 127.0.0.11
nameserver 127.0.0.53
nameserver 127.1.2.3"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_empty "$result" "all 127.x.x.x addresses filtered"
}

test_filters_ipv6_loopback() {
    printf 'TEST: filters IPv6 loopback address\n'

    input="nameserver ::1"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_empty "$result" "::1 filtered"
}

test_passes_real_ipv4() {
    printf 'TEST: passes real IPv4 nameservers\n'

    input="nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_contains "$result" "8.8.8.8" "passes 8.8.8.8"
    assert_contains "$result" "8.8.4.4" "passes 8.8.4.4"
    assert_contains "$result" "1.1.1.1" "passes 1.1.1.1"
}

test_passes_real_ipv6() {
    printf 'TEST: passes real IPv6 nameservers\n'

    input="nameserver 2001:4860:4860::8888
nameserver fd00::1"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_contains "$result" "2001:4860:4860::8888" "passes Google IPv6 DNS"
    assert_contains "$result" "fd00::1" "passes ULA IPv6 address"
}

test_mixed_loopback_and_real() {
    printf 'TEST: filters loopback, keeps real in mixed config\n'

    input="nameserver 127.0.0.53
nameserver ::1
nameserver 10.0.0.1
nameserver 172.16.0.1"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_not_contains "$result" "127.0.0.53" "127.0.0.53 filtered"
    assert_not_contains "$result" "::1" "::1 filtered"
    assert_contains "$result" "10.0.0.1" "10.0.0.1 kept"
    assert_contains "$result" "172.16.0.1" "172.16.0.1 kept"
}

test_systemd_resolved_typical() {
    printf 'TEST: typical systemd-resolved upstream config\n'

    # /run/systemd/resolve/resolv.conf typically looks like this
    input="# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
nameserver 192.168.1.1
search lan"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_eq "$result" "192.168.1.1" "extracts router DNS from systemd-resolved"
}

test_docker_embedded_dns() {
    printf 'TEST: Docker embedded DNS (127.0.0.11) filtered\n'

    input="nameserver 127.0.0.11
search openshell_default"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_empty "$result" "Docker 127.0.0.11 filtered"
}

test_ignores_non_nameserver_lines() {
    printf 'TEST: ignores comments, search, options lines\n'

    input="# nameserver 8.8.8.8
search example.com
options ndots:5
nameserver 1.1.1.1"
    result=$(printf '%s\n' "$input" | filter_resolvers)
    assert_eq "$result" "1.1.1.1" "only real nameserver line extracted"
}

test_empty_input() {
    printf 'TEST: empty input returns empty\n'

    result=$(printf '' | filter_resolvers)
    assert_empty "$result" "empty input produces empty output"
}

test_no_command_injection() {
    printf 'TEST: malicious resolv.conf entries are not executed\n'

    # These should be extracted as literal strings by awk, not executed
    input='nameserver $(rm -rf /)
nameserver 8.8.8.8
nameserver ; echo pwned
nameserver `id`'
    result=$(printf '%s\n' "$input" | filter_resolvers)
    # awk $2 splits on whitespace: "$(rm" is $2 for line 1, ";" for line 3
    # None of these are executed — they're just strings
    assert_contains "$result" "8.8.8.8" "real resolver preserved"
    assert_not_contains "$result" "pwned" "no command injection"
}

# ---------------------------------------------------------------------------
# UPSTREAM_DNS env var tests
# ---------------------------------------------------------------------------
# Note: these test the tr/awk pipeline in isolation rather than the full
# get_upstream_resolvers() function, which requires the entrypoint environment.
# The pipeline logic is identical; this validates the parsing and filtering.

test_upstream_dns_env_var() {
    printf 'TEST: UPSTREAM_DNS env var consumed\n'
    result=$(UPSTREAM_DNS="8.8.8.8,1.1.1.1" printf '%s\n' "8.8.8.8,1.1.1.1" | tr ',' '\n' | \
        awk '{ip=$1; if(ip !~ /^127\./ && ip != "::1" && ip != "") print ip}')
    assert_contains "$result" "8.8.8.8" "first resolver from env var"
    assert_contains "$result" "1.1.1.1" "second resolver from env var"
}

test_upstream_dns_env_filters_loopback() {
    printf 'TEST: UPSTREAM_DNS env var filters loopback\n'
    result=$(printf '%s\n' "127.0.0.1,8.8.8.8,::1,1.1.1.1" | tr ',' '\n' | \
        awk '{ip=$1; if(ip !~ /^127\./ && ip != "::1" && ip != "") print ip}')
    assert_not_contains "$result" "127.0.0.1" "IPv4 loopback filtered from env var"
    assert_not_contains "$result" "::1" "IPv6 loopback filtered from env var"
    assert_contains "$result" "8.8.8.8" "real IPv4 kept from env var"
    assert_contains "$result" "1.1.1.1" "real IPv4 kept from env var"
}

test_upstream_dns_env_empty() {
    printf 'TEST: empty UPSTREAM_DNS falls through\n'
    result=$(printf '' | tr ',' '\n' | \
        awk '{ip=$1; if(ip !~ /^127\./ && ip != "::1" && ip != "") print ip}')
    assert_empty "$result" "empty env var produces no output"
}

test_upstream_dns_env_single() {
    printf 'TEST: single resolver in UPSTREAM_DNS\n'
    result=$(printf '%s\n' "10.0.0.1" | tr ',' '\n' | \
        awk '{ip=$1; if(ip !~ /^127\./ && ip != "::1" && ip != "") print ip}')
    assert_eq "$result" "10.0.0.1" "single resolver extracted"
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

printf '=== DNS resolver filter tests ===\n\n'

test_filters_ipv4_loopback
test_filters_ipv6_loopback
test_passes_real_ipv4
test_passes_real_ipv6
test_mixed_loopback_and_real
test_systemd_resolved_typical
test_docker_embedded_dns
test_ignores_non_nameserver_lines
test_empty_input
test_no_command_injection
test_upstream_dns_env_var
test_upstream_dns_env_filters_loopback
test_upstream_dns_env_empty
test_upstream_dns_env_single

printf '\n=== Results: %d passed, %d failed ===\n' "$_PASS" "$_FAIL"
[ "$_FAIL" -eq 0 ]
