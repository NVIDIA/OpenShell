# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

package openshell.sandbox

default allow_network = false

# --- Static policy data passthrough (queried at sandbox startup) ---

filesystem_policy := data.filesystem_policy

landlock_policy := data.landlock

process_policy := data.process

# --- Network access decision (queried per-CONNECT request) ---

allow_network if {
	network_policy_for_request
}

# --- Deny reasons (specific diagnostics for debugging policy denials) ---

deny_reason := "missing input.network" if {
	not input.network
}

deny_reason := "missing input.exec" if {
	input.network
	not input.exec
}

deny_reason := reason if {
	input.network
	input.exec
	not network_policy_for_request
	endpoint_misses := [r |
		some name
		policy := data.network_policies[name]
		not endpoint_allowed(policy, input.network)
		r := sprintf("endpoint %s:%d not in policy '%s'", [input.network.host, input.network.port, name])
	]
	ancestors_str := concat(" -> ", input.exec.ancestors)
	cmdline_str := concat(", ", input.exec.cmdline_paths)
	binary_misses := [r |
		some name
		policy := data.network_policies[name]
		endpoint_allowed(policy, input.network)
		not binary_allowed(policy, input.exec)
		r := sprintf("binary '%s' (ancestors: [%s], cmdline: [%s]) not allowed in policy '%s'", [input.exec.path, ancestors_str, cmdline_str, name])
	]
	all_reasons := array.concat(endpoint_misses, binary_misses)
	count(all_reasons) > 0
	reason := concat("; ", all_reasons)
}

deny_reason := "network connections not allowed by policy" if {
	input.network
	input.exec
	not network_policy_for_request
	count(data.network_policies) == 0
}

# --- Matched policy name (for audit logging) ---
#
# Collects all matching policy names into a set, then deterministically picks
# the lexicographically smallest.  This avoids a "complete rule conflict" when
# multiple policies cover the same endpoint (e.g. after draft approval adds an
# overlapping rule).

_matching_policy_names contains name if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
}

matched_network_policy := min(_matching_policy_names) if {
	count(_matching_policy_names) > 0
}

# --- Core matching logic ---

# True when at least one network policy matches the request (endpoint + binary).
# Expressed as a boolean so that multiple matching policies don't cause a
# "complete rule conflict".
network_policy_for_request if {
	some name
	data.network_policies[name]
	endpoint_allowed(data.network_policies[name], input.network)
	binary_allowed(data.network_policies[name], input.exec)
}

# Endpoint matching: host (case-insensitive) + port.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	lower(endpoint.host) == lower(network.host)
	endpoint.port == network.port
}

# Endpoint matching: hostless with allowed_ips — match any host on port.
# When an endpoint has allowed_ips but no host, it matches any hostname on the
# given port. The actual IP validation happens in Rust post-DNS-resolution.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	object.get(endpoint, "host", "") == ""
	count(object.get(endpoint, "allowed_ips", [])) > 0
	endpoint.port == network.port
}

# Binary matching: exact path.
# SHA256 integrity is enforced in Rust via trust-on-first-use (TOFU) cache,
# not in Rego. The proxy computes and caches binary hashes at runtime.
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	not contains(b.path, "*")
	b.path == exec.path
}

# Binary matching: ancestor exact path (e.g., claude spawns node).
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	not contains(b.path, "*")
	ancestor := exec.ancestors[_]
	b.path == ancestor
}

# Binary matching: glob pattern against exe path or any ancestor.
# NOTE: cmdline_paths are intentionally excluded — argv[0] is trivially
# spoofable via execve and must not be used as a grant-access signal.
binary_allowed(policy, exec) if {
	some b in policy.binaries
	contains(b.path, "*")
	all_paths := array.concat([exec.path], exec.ancestors)
	some p in all_paths
	glob.match(b.path, ["/"], p)
}

# --- Network action (allow / deny) ---
#
# These rules are mutually exclusive by construction:
#   - "allow" requires `network_policy_for_request` (binary+endpoint matched)
#   - default is "deny" when no policy matches.

default network_action := "deny"

# Explicitly allowed: endpoint + binary match in a network policy → allow.
network_action := "allow" if {
	network_policy_for_request
}

# ===========================================================================
# L7 request evaluation (queried per-request within a tunnel)
# ===========================================================================

default allow_request = false

# L7 request allowed if: L4 policy matches AND the specific endpoint's rules allow the request.
allow_request if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
	some ep
	ep := policy.endpoints[_]
	lower(ep.host) == lower(input.network.host)
	ep.port == input.network.port
	request_allowed_for_endpoint(input.request, ep)
}

# --- L7 deny reason ---

request_deny_reason := reason if {
	input.request
	not allow_request
	reason := sprintf("%s %s not permitted by policy", [input.request.method, input.request.path])
}

# --- L7 rule matching: REST method + path ---

request_allowed_for_endpoint(request, endpoint) if {
	some rule
	rule := endpoint.rules[_]
	rule.allow.method
	method_matches(request.method, rule.allow.method)
	path_matches(request.path, rule.allow.path)
}

# --- L7 rule matching: SQL command ---

request_allowed_for_endpoint(request, endpoint) if {
	some rule
	rule := endpoint.rules[_]
	rule.allow.command
	command_matches(request.command, rule.allow.command)
}

# Wildcard "*" matches any method; otherwise case-insensitive exact match.
method_matches(_, "*") if true

method_matches(actual, expected) if {
	expected != "*"
	upper(actual) == upper(expected)
}

# Path matching: "**" matches everything; otherwise glob.match with "/" delimiter.
path_matches(_, "**") if true

path_matches(actual, pattern) if {
	pattern != "**"
	glob.match(pattern, ["/"], actual)
}

# SQL command matching: "*" matches any; otherwise case-insensitive.
command_matches(_, "*") if true

command_matches(actual, expected) if {
	expected != "*"
	upper(actual) == upper(expected)
}

# --- Matched endpoint config (for L7 and allowed_ips extraction) ---
# Returns the raw endpoint object for the matched policy + host:port.
# Used by Rust to extract L7 config (protocol, tls, enforcement) and/or
# allowed_ips for SSRF allowlist validation.

# Collect all matching endpoint configs into an array to avoid complete-rule
# conflicts when multiple policies cover the same endpoint.  Return the first.
_matching_endpoint_configs := [ep |
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	endpoint_has_extended_config(ep)
]

matched_endpoint_config := _matching_endpoint_configs[0] if {
	count(_matching_endpoint_configs) > 0
}

# Hosted endpoint: match on host (case-insensitive) + port.
endpoint_matches_request(ep, network) if {
	lower(ep.host) == lower(network.host)
	ep.port == network.port
}

# Hostless endpoint with allowed_ips: match on port only.
endpoint_matches_request(ep, network) if {
	object.get(ep, "host", "") == ""
	count(object.get(ep, "allowed_ips", [])) > 0
	ep.port == network.port
}

# An endpoint has extended config if it specifies L7 protocol or allowed_ips.
endpoint_has_extended_config(ep) if {
	ep.protocol
}

endpoint_has_extended_config(ep) if {
	count(object.get(ep, "allowed_ips", [])) > 0
}
