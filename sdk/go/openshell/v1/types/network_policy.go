// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// NetworkPolicyRule defines a named network policy rule containing endpoints and binaries.
type NetworkPolicyRule struct {
	// Name is the map key for this rule in the sandbox policy.
	Name string
	// Endpoints lists the network endpoints governed by this rule.
	Endpoints []PolicyNetworkEndpoint
	// Binaries lists the binaries governed by this rule.
	Binaries []PolicyNetworkBinary
}

// PolicyNetworkEndpoint describes a full network endpoint with its access controls
// as used in sandbox network policy rules. This is distinct from [NetworkEndpoint]
// which is the simplified profile-level endpoint (Host, Port, Protocol only).
type PolicyNetworkEndpoint struct {
	Host                         string
	Port                         uint32
	Ports                        []uint32
	Protocol                     string
	TLS                          string
	Enforcement                  string
	Access                       string
	Rules                        []L7Rule
	AllowedIPs                   []string
	DenyRules                    []L7DenyRule
	AllowEncodedSlash            bool
	PersistedQueries             string
	GraphqlPersistedQueries      map[string]GraphqlOperation
	GraphqlMaxBodyBytes          uint32
	Path                         string
	WebsocketCredentialRewrite   bool
	RequestBodyCredentialRewrite bool
	AdvisorProposed              bool
	CredentialSigning            string
	SigningService               string
	SigningRegion                string
	JsonRpcMaxBodyBytes          uint32
	Mcp                          *McpOptions
}

// PolicyNetworkBinary identifies a binary subject to network policy enforcement.
// This is distinct from [NetworkBinary] which is the simplified profile-level binary.
type PolicyNetworkBinary struct {
	// Path is the filesystem path to the binary.
	Path string
}

// L7Rule wraps an L7 allow rule.
type L7Rule struct {
	// Allow holds the layer-7 allow criteria.
	Allow *L7Allow
}

// L7Allow specifies layer-7 allow criteria for HTTP/GraphQL/MCP traffic.
type L7Allow struct {
	Method        string
	Path          string
	Command       string
	Query         map[string]L7QueryMatcher
	OperationType string
	OperationName string
	Fields        []string
	Params        map[string]L7QueryMatcher
}

// L7DenyRule specifies layer-7 deny criteria for HTTP/GraphQL/MCP traffic.
type L7DenyRule struct {
	Method        string
	Path          string
	Command       string
	Query         map[string]L7QueryMatcher
	OperationType string
	OperationName string
	Fields        []string
	Params        map[string]L7QueryMatcher
}

// McpOptions holds MCP-specific policy and inspection options.
type McpOptions struct {
	StrictToolNames         *bool
	AllowAllKnownMcpMethods *bool
}

// L7QueryMatcher matches query parameters by glob pattern or exact values.
type L7QueryMatcher struct {
	Glob string
	Any  []string
}

// GraphqlOperation describes a GraphQL operation for persisted-query validation.
type GraphqlOperation struct {
	OperationType string
	OperationName string
	Fields        []string
}

// --- MergeOperation types ---

// PolicyMergeOperation represents a single atomic policy mutation.
// Exactly one of the pointer fields must be non-nil, modelling the proto oneof.
type PolicyMergeOperation struct {
	// AddRule adds a new named network policy rule.
	AddRule *AddNetworkRule
	// RemoveEndpoint removes a single endpoint from a rule.
	RemoveEndpoint *RemoveNetworkEndpoint
	// RemoveRule removes an entire named rule.
	RemoveRule *RemoveNetworkRule
	// AddDenyRules appends deny rules to an endpoint.
	AddDenyRules *AddDenyRules
	// AddAllowRules appends allow rules to an endpoint.
	AddAllowRules *AddAllowRules
	// RemoveBinary removes a binary from a rule.
	RemoveBinary *RemoveNetworkBinary
}

// AddNetworkRule adds a named network policy rule with a full rule definition.
type AddNetworkRule struct {
	// RuleName is the name key for the rule.
	RuleName string
	// Rule is the full network policy rule to add.
	Rule NetworkPolicyRule
}

// RemoveNetworkEndpoint removes a specific endpoint from a named rule.
type RemoveNetworkEndpoint struct {
	// RuleName is the name of the rule containing the endpoint.
	RuleName string
	// Host is the endpoint host to remove.
	Host string
	// Port is the endpoint port to remove.
	Port uint32
}

// RemoveNetworkRule removes an entire named rule from the policy.
type RemoveNetworkRule struct {
	// RuleName is the name of the rule to remove.
	RuleName string
}

// AddDenyRules appends layer-7 deny rules to a specific endpoint.
type AddDenyRules struct {
	// Host identifies the target endpoint host.
	Host string
	// Port identifies the target endpoint port.
	Port uint32
	// DenyRules are the deny rules to append.
	DenyRules []L7DenyRule
}

// AddAllowRules appends layer-7 allow rules to a specific endpoint.
type AddAllowRules struct {
	// Host identifies the target endpoint host.
	Host string
	// Port identifies the target endpoint port.
	Port uint32
	// Rules are the allow rules to append.
	Rules []L7Rule
}

// RemoveNetworkBinary removes a binary from a named rule.
type RemoveNetworkBinary struct {
	// RuleName is the name of the rule containing the binary.
	RuleName string
	// BinaryPath is the filesystem path of the binary to remove.
	BinaryPath string
}
