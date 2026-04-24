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
		r := sprintf("binary '%s' not allowed in policy '%s' (ancestors: [%s], cmdline: [%s]). SYMLINK HINT: the binary path is the kernel-resolved target from /proc/<pid>/exe, not the symlink. If your policy specifies a symlink (e.g., /usr/bin/python3) but the actual binary is /usr/bin/python3.11, either: (1) use the canonical path in your policy (run 'readlink -f /usr/bin/python3' inside the sandbox), or (2) ensure symlink resolution is working (check sandbox logs for 'Cannot access container filesystem')", [input.exec.path, name, ancestors_str, cmdline_str])
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

# Endpoint matching: exact host (case-insensitive) + port in ports list.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	not contains(endpoint.host, "*")
	lower(endpoint.host) == lower(network.host)
	endpoint.ports[_] == network.port
}

# Endpoint matching: glob host pattern + port in ports list.
# Uses "." as delimiter so "*" matches a single DNS label and "**" matches
# across label boundaries — consistent with TLS certificate wildcard semantics.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	contains(endpoint.host, "*")
	glob.match(lower(endpoint.host), ["."], lower(network.host))
	endpoint.ports[_] == network.port
}

# Endpoint matching: hostless with allowed_ips — match any host on port.
# When an endpoint has allowed_ips but no host, it matches any hostname on the
# given port. The actual IP validation happens in Rust post-DNS-resolution.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	object.get(endpoint, "host", "") == ""
	count(object.get(endpoint, "allowed_ips", [])) > 0
	endpoint.ports[_] == network.port
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

# Per-policy helper: true when this single policy has at least one endpoint
# matching the L4 request whose L7 rules also permit the specific request.
# Isolating the endpoint iteration inside a function avoids the regorus
# "duplicated definition of local variable" error that occurs when the
# outer `some name` iterates over multiple policies that share a host:port.
_policy_allows_l7(policy) if {
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	request_allowed_for_endpoint(input.request, ep)
}

# L7 request allowed if any matching L4 policy also allows the L7 request
# AND no deny rule blocks it. Deny rules take precedence over allow rules.
allow_request if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
	_policy_allows_l7(policy)
	not deny_request
}

# --- L7 deny rules ---
#
# Deny rules are evaluated after allow rules and take precedence.
# If a request matches any deny rule on any matching endpoint, it is blocked
# even if it would otherwise be allowed.

default deny_request = false

# Per-policy helper: true when this policy has at least one endpoint matching
# the L4 request whose deny_rules also match the specific L7 request.
_policy_denies_l7(policy) if {
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	request_denied_for_endpoint(input.request, ep)
}

deny_request if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
	_policy_denies_l7(policy)
}

# --- L7 deny rule matching: REST method + path + query ---

request_denied_for_endpoint(request, endpoint) if {
	some deny_rule
	deny_rule := endpoint.deny_rules[_]
	deny_rule.method
	method_matches(request.method, deny_rule.method)
	path_matches(request.path, deny_rule.path)
	deny_query_params_match(request, deny_rule)
}

# --- L7 deny rule matching: SQL command ---

request_denied_for_endpoint(request, endpoint) if {
	some deny_rule
	deny_rule := endpoint.deny_rules[_]
	deny_rule.command
	command_matches(request.command, deny_rule.command)
}

# Deny query matching: fail-closed semantics.
# If no query rules on the deny rule, match unconditionally (any query params).
# If query rules present, trigger the deny if ANY value for a configured key
# matches the matcher. This is the inverse of allow-side semantics where ALL
# values must match. For deny logic, a single matching value is enough to block.
deny_query_params_match(request, deny_rule) if {
	deny_query_rules := object.get(deny_rule, "query", {})
	count(deny_query_rules) == 0
}

deny_query_params_match(request, deny_rule) if {
	deny_query_rules := object.get(deny_rule, "query", {})
	count(deny_query_rules) > 0
	not deny_query_key_missing(request, deny_query_rules)
	not deny_query_value_mismatch_all(request, deny_query_rules)
}

# A configured deny query key is missing from the request entirely.
# Missing key means the deny rule doesn't apply (fail-open on absence).
deny_query_key_missing(request, query_rules) if {
	some key
	query_rules[key]
	request_query := object.get(request, "query_params", {})
	values := object.get(request_query, key, null)
	values == null
}

# ALL values for a configured key fail to match the matcher.
# If even one value matches, deny fires. This rule checks the opposite:
# true when NO value matches (i.e., every value is a mismatch).
deny_query_value_mismatch_all(request, query_rules) if {
	some key
	matcher := query_rules[key]
	request_query := object.get(request, "query_params", {})
	values := object.get(request_query, key, [])
	count(values) > 0
	not deny_any_value_matches(values, matcher)
}

# True if at least one value in the list matches the matcher.
deny_any_value_matches(values, matcher) if {
	some i
	query_value_matches(values[i], matcher)
}

# --- L7 deny reason ---

request_deny_reason := reason if {
	input.request
	deny_request
	reason := sprintf("%s %s blocked by deny rule", [input.request.method, input.request.path])
}

request_deny_reason := reason if {
	input.request
	not deny_request
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
	query_params_match(request, rule)
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
#
# INVARIANT: `input.request.path` is canonicalized by the sandbox before
# policy evaluation — percent-decoded, dot-segments resolved, doubled
# slashes collapsed, `;params` stripped, `%2F` rejected (unless an
# endpoint opts in). Patterns here must therefore match canonical paths;
# do not attempt defensive matching against `..` or `%2e%2e` — those
# inputs are rejected at the L7 parser boundary before this rule runs.
path_matches(_, "**") if true

path_matches(actual, pattern) if {
	pattern != "**"
	glob.match(pattern, ["/"], actual)
}

# Query matching:
# - If no query rules are configured, allow any query params.
# - For configured keys, all request values for that key must match.
# - Matcher shape supports either `glob` or `any`.
query_params_match(request, rule) if {
	query_rules := object.get(rule.allow, "query", {})
	not query_mismatch(request, query_rules)
}

query_mismatch(request, query_rules) if {
	some key
	matcher := query_rules[key]
	not query_key_matches(request, key, matcher)
}

query_key_matches(request, key, matcher) if {
	request_query := object.get(request, "query_params", {})
	values := object.get(request_query, key, null)
	values != null
	count(values) > 0
	not query_value_mismatch(values, matcher)
}

query_value_mismatch(values, matcher) if {
	some i
	value := values[i]
	not query_value_matches(value, matcher)
}

query_value_matches(value, matcher) if {
	is_string(matcher)
	glob.match(matcher, [], value)
}

query_value_matches(value, matcher) if {
	is_object(matcher)
	glob_pattern := object.get(matcher, "glob", "")
	glob_pattern != ""
	glob.match(glob_pattern, [], value)
}

query_value_matches(value, matcher) if {
	is_object(matcher)
	any_patterns := object.get(matcher, "any", [])
	count(any_patterns) > 0
	some i
	glob.match(any_patterns[i], [], value)
}

# SQL command matching: "*" matches any; otherwise case-insensitive.
command_matches(_, "*") if true

command_matches(actual, expected) if {
	expected != "*"
	upper(actual) == upper(expected)
}

# --- Matched endpoint config (for L7 and allowed_ips extraction) ---
# Returns the raw endpoint object for the matched policy + host:port.
# Used by Rust to extract L7 config (protocol, tls, enforcement,
# allow_encoded_slash) and/or allowed_ips for SSRF allowlist validation.

# Per-policy helper: returns matching endpoint configs for a single policy.
_policy_endpoint_configs(policy) := [ep |
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	endpoint_has_extended_config(ep)
]

# Collect matching endpoint configs across all policies.  Iterates over
# _matching_policy_names (a set, safe from regorus variable collisions)
# then collects per-policy configs via the helper function.
_matching_endpoint_configs := [cfg |
	some pname
	_matching_policy_names[pname]
	cfgs := _policy_endpoint_configs(data.network_policies[pname])
	cfg := cfgs[_]
]

matched_endpoint_config := _matching_endpoint_configs[0] if {
	count(_matching_endpoint_configs) > 0
}

# Hosted endpoint: exact host match + port in ports list.
endpoint_matches_request(ep, network) if {
	not contains(ep.host, "*")
	lower(ep.host) == lower(network.host)
	ep.ports[_] == network.port
}

# Hosted endpoint: glob host match + port in ports list.
endpoint_matches_request(ep, network) if {
	contains(ep.host, "*")
	glob.match(lower(ep.host), ["."], lower(network.host))
	ep.ports[_] == network.port
}

# Hostless endpoint with allowed_ips: match on port only.
endpoint_matches_request(ep, network) if {
	object.get(ep, "host", "") == ""
	count(object.get(ep, "allowed_ips", [])) > 0
	ep.ports[_] == network.port
}

# An endpoint has extended config if it specifies L7 protocol, allowed_ips,
# or an explicit tls mode (e.g. tls: skip).
endpoint_has_extended_config(ep) if {
	ep.protocol
}

endpoint_has_extended_config(ep) if {
	count(object.get(ep, "allowed_ips", [])) > 0
}

endpoint_has_extended_config(ep) if {
	ep.tls
}
