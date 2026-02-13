package navigator.sandbox

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

deny_reason := "no network policies defined" if {
	input.network
	input.exec
	count(data.network_policies) == 0
}

# --- Matched policy name (for audit logging) ---

matched_network_policy := name if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
}

# --- Core matching logic ---

# Find a policy where both endpoint and binary match the request.
# Note: if multiple policies match, OPA will error (complete rule conflict).
# This is intentional — well-authored policies should have disjoint coverage.
network_policy_for_request := policy if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
}

# Endpoint matching: host (case-insensitive) + port.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	lower(endpoint.host) == lower(network.host)
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
	some ancestor
	ancestor := exec.ancestors[_]
	b.path == ancestor
}

# Binary matching: cmdline exact path (script interpreters — e.g. node runs claude script).
# When /usr/local/bin/claude has shebang #!/usr/bin/env node, the exe is /usr/bin/node
# but cmdline contains /usr/local/bin/claude as an argv entry.
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	not contains(b.path, "*")
	some cp
	cp := exec.cmdline_paths[_]
	b.path == cp
}

# Binary matching: glob pattern against path, any ancestor, or any cmdline path.
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	contains(b.path, "*")
	all_paths := array.concat(array.concat([exec.path], exec.ancestors), exec.cmdline_paths)
	some p
	p := all_paths[_]
	glob.match(b.path, ["/"], p)
}
